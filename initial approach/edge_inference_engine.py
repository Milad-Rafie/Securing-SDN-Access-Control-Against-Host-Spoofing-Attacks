#!/usr/bin/env python3

import os
import time
import logging
from collections import defaultdict

import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from p4runtime_lib import bmv2, helper
from p4runtime_lib.switch import ShutdownAllSwitchConnections

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LocalEdgeInferenceEngine:
    """
    Local ML + P4Runtime controller for a single BMv2 switch.
    """

    def __init__(self, switch_name, grpc_addr, device_id,
                 p4info_file, bmv2_json):
        self.switch_name = switch_name
        self.grpc_addr = grpc_addr
        self.device_id = device_id
        self.p4info_file = p4info_file
        self.bmv2_json = bmv2_json

        # P4Runtime helper & connection
        self.p4info_helper = helper.P4InfoHelper(self.p4info_file)
        self.switch = None

        # ML model state
        self.model = None
        self.scaler = None
        self.risk_threshold_low = 30
        self.risk_threshold_high = 70

        # Flow tracking
        self.flow_features = defaultdict(dict)
        self.flow_decisions = {}

    # ---------- P4Runtime connection ----------

    def connect_and_configure(self):
        """Connect to switch via P4Runtime and push pipeline."""
        logger.info(
            f"[{self.switch_name}] Connecting to {self.grpc_addr} (device_id={self.device_id})"
        )
        self.switch = bmv2.Bmv2SwitchConnection(
            name=self.switch_name,
            address=self.grpc_addr,
            device_id=self.device_id,
            proto_dump_file=None,
        )

        # Become master
        self.switch.MasterArbitrationUpdate()

        # Set forwarding pipeline (P4Info + JSON)
        self.switch.SetForwardingPipelineConfig(
            p4info=self.p4info_helper.p4info,
            bmv2_json_file_path=self.bmv2_json,
        )
        logger.info(f"[{self.switch_name}] Pipeline configured with {self.bmv2_json}")


    def install_base_routing(self):
        """
        Install static ipv4_lpm rules so pingall works.

        Topology:
          - s1: ports 1(h1), 2(h2), 3(link to s2)
          - s2: ports 1(link to s1), 2(h3), 3(h4)
          - Hosts: 10.0.0.1 (h1), 10.0.0.2 (h2), 10.0.0.3 (h3), 10.0.0.4 (h4)
        """
        logger.info(f"[{self.switch_name}] Installing base ipv4_lpm routes")

        if self.switch_name == "s1":
            rules = [
                # local hosts
                ("10.0.0.1", 32, 1),
                ("10.0.0.2", 32, 2),
                # hosts behind s2 via port 3
                ("10.0.0.3", 32, 3),
                ("10.0.0.4", 32, 3),
            ]
        elif self.switch_name == "s2":
            rules = [
                # local hosts
                ("10.0.0.3", 32, 2),
                ("10.0.0.4", 32, 3),
                # hosts behind s1 via port 1
                ("10.0.0.1", 32, 1),
                ("10.0.0.2", 32, 1),
            ]
        else:
            logger.warning(
                f"[{self.switch_name}] Unknown switch_name for base routing, skipping"
            )
            return

        #  table entries
        for ip, prefix_len, port in rules:
            table_entry = self.p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_lpm",
                match_fields={"hdr.ipv4.dstAddr": (ip, prefix_len)},
                action_name="MyIngress.forward",
                action_params={"port": port},
            )
            self.switch.WriteTableEntry(table_entry)
            logger.info(
                f"[{self.switch_name}] ipv4_lpm: {ip}/{prefix_len} -> port {port}"
            )

    # ---------- ML pieces (for later) ----------

    def load_models(self, model_path, scaler_path):
        """Load pre-trained ML model + scaler."""
        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        logger.info(
            f"[{self.switch_name}] Loaded model {model_path} and scaler {scaler_path}"
        )

    def train_model_locally(self, training_data):
        """
        Train Isolation Forest on local normal traffic.

        training_data: pandas DataFrame with columns:
          ['packet_count', 'byte_count', 'avg_iat', 'avg_pkt_size']
        """
        X = training_data[
            ["packet_count", "byte_count", "avg_iat", "avg_pkt_size"]
        ].values
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
        )
        self.model.fit(X_scaled)
        logger.info(f"[{self.switch_name}] Local model trained")

    def compute_risk_score(self, flow_features):
        """
        Compute risk score (0-100) using Isolation Forest.
        """
        try:
            X = np.array(
                [
                    [
                        flow_features["packet_count"],
                        flow_features["byte_count"],
                        flow_features["avg_iat"],
                        flow_features["avg_pkt_size"],
                    ]
                ]
            )
            X_scaled = self.scaler.transform(X)
            anomaly_score = self.model.decision_function(X_scaled)[0]
            # Simple mapping: more negative -> higher risk
            risk = 50 - 50 * anomaly_score
            return int(max(0, min(100, risk)))
        except Exception as e:
            logger.error(f"[{self.switch_name}] Risk computation failed: {e}")
            return 50

    def get_access_decision(self, risk_score):
        if risk_score < self.risk_threshold_low:
            return "ALLOW"
        elif risk_score < self.risk_threshold_high:
            return "MFA"
        else:
            return "QUARANTINE"

    def process_feature_digest(self, digest_data):
        """
        Placeholder for when you wire actual digests from P4.

        digest_data should contain:
          - flow_id
          - packet_count
          - byte_count
          - iat_sum
        """
        flow_id = digest_data["flow_id"]
        pkt_cnt = digest_data["packet_count"]
        byte_cnt = digest_data["byte_count"]
        iat_sum = digest_data["iat_sum"]

        avg_iat = iat_sum / pkt_cnt if pkt_cnt > 0 else 0
        avg_pkt_size = byte_cnt / pkt_cnt if pkt_cnt > 0 else 0

        flow_features = {
            "packet_count": pkt_cnt,
            "byte_count": byte_cnt,
            "avg_iat": avg_iat,
            "avg_pkt_size": avg_pkt_size,
        }

        risk = self.compute_risk_score(flow_features)
        decision = self.get_access_decision(risk)

        self.flow_decisions[flow_id] = {
            "risk_score": risk,
            "decision": decision,
            "timestamp": time.time(),
        }
        logger.info(
            f"[{self.switch_name}] Flow {flow_id}: risk={risk}, decision={decision}"
        )

    def close(self):
        pass  # we call ShutdownAllSwitchConnections() in main()


def main():
    
    P4INFO_FILE = os.path.expanduser(
        "~/p4_project/src/behavioral_acl_p4info.txtpb"
    )
    BMV2_JSON = os.path.expanduser(
        "~/p4_project/src/behavioral_acl.json"
    )

    # Create engines for both switches
    s1_engine = LocalEdgeInferenceEngine(
        switch_name="s1",
        grpc_addr="127.0.0.1:50051",
        device_id=1,
        p4info_file=P4INFO_FILE,
        bmv2_json=BMV2_JSON,
    )

    s2_engine = LocalEdgeInferenceEngine(
        switch_name="s2",
        grpc_addr="127.0.0.1:50052",
        device_id=2,
        p4info_file=P4INFO_FILE,
        bmv2_json=BMV2_JSON,
    )

    try:
        s1_engine.connect_and_configure()
        s2_engine.connect_and_configure()

        s1_engine.install_base_routing()
        s2_engine.install_base_routing()

        logger.info(
            "Base routing installed on s1 and s2. You can now run pingall in Mininet."
        )

    finally:
        ShutdownAllSwitchConnections()


if __name__ == "__main__":
    main()
