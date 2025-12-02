"""
Behavioral Flow Authentication Controller for POX
Uses an XGBoost model trained on InSDN top-12 features for real-time attack detection.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.addresses import EthAddr
from pox.lib.recoco import Timer

import time
import joblib
import numpy as np
from collections import defaultdict
import os

log = core.getLogger()

# ---------------------------------------------------------------------------
# Paths to model, scaler, and feature names (update if needed)
# ---------------------------------------------------------------------------
MODEL_PATH = os.path.expanduser('~/Documents/UNI/SDN/sdn_behavioral_auth/xgb_topk.pkl')
SCALER_PATH = os.path.expanduser('~/Documents/UNI/SDN/sdn_behavioral_auth/scaler_topk.pkl')
FEATURE_NAMES_PATH = os.path.expanduser('~/Documents/UNI/SDN/sdn_behavioral_auth/feature_names_topk.pkl')

# In your InSDN training, BinaryLabel = 1 means "attack"
ATTACK_LABEL = 1


class BehavioralAuthController(object):
    def __init__(self):
        log.info("=" * 60)
        log.info("Behavioral Authentication Controller Starting (XGBoost top-k)...")
        log.info("=" * 60)

        # -------------------------------------------------------------------
        # Load trained XGBoost model, scaler, and feature names
        # -------------------------------------------------------------------
        try:
            self.model = joblib.load(MODEL_PATH)
            self.scaler = joblib.load(SCALER_PATH)
            self.feature_names = joblib.load(FEATURE_NAMES_PATH)

            log.info("✓ XGBoost model loaded from: %s", MODEL_PATH)
            log.info("✓ Scaler loaded from: %s", SCALER_PATH)
            log.info("✓ Feature names loaded from: %s", FEATURE_NAMES_PATH)
            log.info("Number of features: %d", len(self.feature_names))
            log.info("Feature order: %s", self.feature_names)

            # Sanity checks
            try:
                log.info("Scaler n_features_in_: %s", getattr(self.scaler, 'n_features_in_', 'N/A'))
                log.info("Model n_features_in_: %s", getattr(self.model, 'n_features_in_', 'N/A'))
            except Exception as e:
                log.warning("Could not read n_features_in_ from scaler/model: %s", e)

            # Determine which predict_proba column corresponds to ATTACK_LABEL
            self.attack_class_index = None
            try:
                classes_list = list(getattr(self.model, 'classes_', []))
                log.info("Model classes_: %s", classes_list)
                if ATTACK_LABEL in classes_list:
                    self.attack_class_index = classes_list.index(ATTACK_LABEL)
                    log.info("ATTACK_LABEL=%s mapped to predict_proba index %d",
                             ATTACK_LABEL, self.attack_class_index)
                else:
                    log.error("ATTACK_LABEL=%s not found in model.classes_! "
                              "Defaulting to last class index.", ATTACK_LABEL)
                    if classes_list:
                        self.attack_class_index = len(classes_list) - 1
            except Exception as e:
                log.error("Error determining attack_class_index: %s", e)

        except Exception as e:
            log.error("✗ Failed to load ML artifacts (model/scaler/features): %s", e)
            return

        # -------------------------------------------------------------------
        # Data structures for flow stats & host risk
        # -------------------------------------------------------------------
        self.connections = {}

        # Per-flow statistics:
        # Flow key is "src_mac->dst_mac" (unidirectional)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': time.time(),
            'last_seen': time.time(),
            'duration': 0.0,

            # Directional forward stats (src_mac -> dst_mac)
            'fwd_packets': 0,
            'fwd_bytes': 0,
            'fwd_header_len': 0,       # sum of header bytes in forward direction
            'last_fwd_time': None,
            'fwd_iat_tot': 0.0,        # total IAT (seconds) in forward direction
            'fwd_iat_max': 0.0,        # max IAT (seconds) in forward direction
            'init_fwd_win_bytes': 0,   # TCP window size of first forward TCP packet
            'fwd_pkt_len_min': float('inf'),
            'fwd_pkt_len_max': 0,

            # Flow-wide stats
            'pkt_len_max': 0,          # max packet length (this direction)
            'dst_port': 0,             # destination TCP/UDP port
            'syn_flag_cnt': 0          # SYN flags count (this direction)
        })

        # Risk scores per MAC and blocked hosts
        self.host_risk_scores = defaultdict(float)
        self.blocked_hosts = set()

        # Risk threshold (0-100); tune as needed
        self.RISK_THRESHOLD = 75.0

        # Listen for OpenFlow events
        core.openflow.addListeners(self)

        # Start periodic monitoring
        Timer(10, self._monitor_flows, recurring=True)

        log.info("✓ Controller initialized")
        log.info("✓ Monitoring interval: 10 seconds")
        log.info("✓ Risk threshold: %.1f", self.RISK_THRESHOLD)
        log.info("=" * 60)

    # -----------------------------------------------------------------------
    # OpenFlow event handlers
    # -----------------------------------------------------------------------
    def _handle_ConnectionUp(self, event):
        """Handle new switch connection."""
        self.connections[event.dpid] = event.connection
        log.info("Switch %s connected", dpid_to_str(event.dpid))

        # Install table-miss entry: send unknown packets to controller
        msg = of.ofp_flow_mod()
        msg.priority = 0
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(msg)

    def _handle_PacketIn(self, event):
        """Handle PacketIn events from switches and update flow stats."""
        # Some packets (e.g. ICMP errors) can cause POX's parser to throw
        # AttributeError deep inside pox.lib.packet. Catch & skip them.
        try:
            packet = event.parsed
        except Exception as e:
            log.error("Error parsing packet in PacketIn; skipping. Exception: %s", e)
            return

        dpid = event.dpid
        inport = event.port

        src_mac = str(packet.src)
        dst_mac = str(packet.dst)

        # Skip broadcast/multicast and IPv6 multicast
        if dst_mac == "ff:ff:ff:ff:ff:ff" or dst_mac.startswith("33:33:"):
            self._forward_packet(event, packet, dpid, inport)
            return

        # Only analyze unicast flows between Mininet hosts (00:00:00:00:00:XX)
        if not src_mac.startswith("00:00:00:00:00:") or not dst_mac.startswith("00:00:00:00:00:"):
            self._forward_packet(event, packet, dpid, inport)
            return

        # Blocked host check
        if src_mac in self.blocked_hosts:
            log.warning("⛔ DROPPED packet from blocked host %s", src_mac)
            return

        # -------------------------------------------------------------------
        # Update per-flow statistics
        # -------------------------------------------------------------------
        flow_key = f"{src_mac}->{dst_mac}"
        stats = self.flow_stats[flow_key]

        packet_len = len(packet)
        current_time = time.time()

        # Basic counters
        stats['packet_count'] += 1
        stats['byte_count'] += packet_len

        if stats['packet_count'] == 1:
            stats['start_time'] = current_time

        stats['last_seen'] = current_time
        stats['duration'] = stats['last_seen'] - stats['start_time']

        # Forward direction (src -> dst)
        stats['fwd_packets'] += 1
        stats['fwd_bytes'] += packet_len

        # Max packet length (this direction)
        if packet_len > stats['pkt_len_max']:
            stats['pkt_len_max'] = packet_len

        # Fwd Pkt Len Min/Max
        if packet_len < stats['fwd_pkt_len_min']:
            stats['fwd_pkt_len_min'] = packet_len
        if packet_len > stats['fwd_pkt_len_max']:
            stats['fwd_pkt_len_max'] = packet_len

        # Parse headers for ports and TCP flags
        ip = packet.find('ipv4')
        tcp = packet.find('tcp')
        udp = packet.find('udp')

        # Destination port (from first L4 packet we see)
        if stats['dst_port'] == 0 and (tcp or udp):
            try:
                if tcp:
                    stats['dst_port'] = tcp.dstport
                elif udp:
                    stats['dst_port'] = udp.dstport
            except Exception:
                pass

        # Header length approximation (forward direction)
        hdr_len = 0
        try:
            if ip is not None:
                # ip.header_length is often in 32-bit words -> * 4 bytes
                ihl = getattr(ip, 'header_length', 0)
                hdr_len += ihl * 4
        except Exception:
            pass

        try:
            if tcp is not None:
                # TCP header length in 32-bit words, sometimes named 'off' or 'hdr_len'
                thl = getattr(tcp, 'off', getattr(tcp, 'hdr_len', 5))
                hdr_len += thl * 4
            elif udp is not None:
                hdr_len += 8  # UDP header is typically 8 bytes
        except Exception:
            pass

        stats['fwd_header_len'] += hdr_len

        # Forward IATs (seconds)
        if stats['last_fwd_time'] is not None:
            delta = current_time - stats['last_fwd_time']
            stats['fwd_iat_tot'] += delta
            if delta > stats['fwd_iat_max']:
                stats['fwd_iat_max'] = delta
        stats['last_fwd_time'] = current_time

        # TCP-specific stats
        if tcp is not None:
            # SYN flag count in this direction
            try:
                if tcp.SYN:
                    stats['syn_flag_cnt'] += 1
            except Exception:
                pass

            # Initial forward window size (first TCP packet in this direction)
            if stats['init_fwd_win_bytes'] == 0:
                try:
                    stats['init_fwd_win_bytes'] = getattr(tcp, 'window', 0)
                except Exception:
                    pass

        # Finally, forward packet normally (learning-switch style)
        self._forward_packet(event, packet, dpid, inport)

    def _forward_packet(self, event, packet, dpid, inport):
        """
        Forward packet using simple flooding.

        IMPORTANT:h
        - We must both send the current packet out (ofp_packet_out)
          AND (optionally) install a flow_mod for future packets.
        """

        # 1) Send the current packet out (so ping/ARP actually works)
        po = of.ofp_packet_out()
        po.data = event.ofp          # raw OpenFlow packet data
        po.in_port = inport
        po.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(po)

        # 2) (Optional) Install a flow_mod so future packets of this flow are flooded in the datapath
        fm = of.ofp_flow_mod()
        fm.match = of.ofp_match.from_packet(packet, inport)
        fm.idle_timeout = 30
        fm.hard_timeout = 60
        fm.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        # If the switch buffered the original packet, we can tie it to this flow_mod
        fm.buffer_id = event.ofp.buffer_id
        event.connection.send(fm)

    # -----------------------------------------------------------------------
    # Periodic flow monitoring & risk assessment
    # -----------------------------------------------------------------------
    def _monitor_flows(self):
        """Periodic analysis of flows and risk scoring."""
        log.info("\n" + "=" * 60)
        log.info("🔍 Running Behavioral Analysis...")
        log.info("=" * 60)

        current_time = time.time()
        analyzed_flows = 0

        for flow_key, stats in list(self.flow_stats.items()):
            try:
                src_mac, dst_mac = flow_key.split('->')
            except ValueError:
                continue

            # Skip blocked hosts
            if src_mac in self.blocked_hosts:
                continue

            # Require at least a few packets to analyze
            if stats['packet_count'] < 5:
                continue

            analyzed_flows += 1

            # Reverse flow stats for backward features
            reverse_key = f"{dst_mac}->{src_mac}"
            rev_stats = self.flow_stats.get(reverse_key, None)

            # Extract features (top-12) for model input
            try:
                features = self._extract_features(stats, rev_stats)
                log.debug("Feature vector for %s: %s", flow_key, features)

                # Calculate risk
                risk_score = self._calculate_risk(features)
                self.host_risk_scores[src_mac] = risk_score

                if risk_score >= self.RISK_THRESHOLD:
                    log.warning("🚨 ANOMALY | Flow: %s | Risk: %.1f%%", flow_key, risk_score)
                    self._block_host(src_mac)
                else:
                    log.info("✅ NORMAL  | Flow: %s | Risk: %.1f%%", flow_key, risk_score)

            except Exception as e:
                log.error("Error analyzing flow %s: %s", flow_key, e)
                continue

        log.info("Flows analyzed this round: %d, total tracked flows: %d",
                 analyzed_flows, len(self.flow_stats))
        log.info("Total blocked hosts: %d", len(self.blocked_hosts))
        log.info("=" * 60 + "\n")

    # -----------------------------------------------------------------------
    # Feature extraction – must match training (top-12 InSDN features)
    # -----------------------------------------------------------------------
    def _extract_features(self, stats, rev_stats):
        """
        Extract the 12 features used in the XGBoost top-k model.

        Top 12 selected features:
        - Pkt Size Avg
        - Pkt Len Max
        - Pkt Len Mean
        - SYN Flag Cnt
        - Bwd IAT Tot
        - Init Bwd Win Byts
        - Dst Port
        - Bwd Header Len
        - Fwd Pkt Len Min
        - Tot Bwd Pkts
        - Bwd IAT Max
        - Fwd Pkt Len Max
        """

        pkt_count = max(stats['packet_count'], 1)

        # Forward-only values (this direction)
        pkt_size_avg = stats['byte_count'] / pkt_count          # Pkt Size Avg
        pkt_len_max = stats['pkt_len_max']                      # Pkt Len Max
        pkt_len_mean = stats['byte_count'] / pkt_count          # Pkt Len Mean
        syn_flag_cnt = stats['syn_flag_cnt']                    # SYN Flag Cnt
        dst_port = stats['dst_port']                            # Dst Port
        fwd_pkt_len_min = stats['fwd_pkt_len_min']
        if fwd_pkt_len_min == float('inf'):
            fwd_pkt_len_min = 0
        fwd_pkt_len_max = stats['fwd_pkt_len_max']

        # Backward-related values from reverse flow (if exists)
        if rev_stats is not None:
            tot_bwd_pkts = rev_stats['fwd_packets']             # Tot Bwd Pkts
            bwd_header_len = rev_stats['fwd_header_len']        # Bwd Header Len
            bwd_iat_tot = rev_stats['fwd_iat_tot'] * 1e6        # seconds -> microseconds
            bwd_iat_max = rev_stats['fwd_iat_max'] * 1e6        # seconds -> microseconds
            init_bwd_win_bytes = rev_stats['init_fwd_win_bytes']  # Init Bwd Win Byts
        else:
            tot_bwd_pkts = 0
            bwd_header_len = 0
            bwd_iat_tot = 0.0
            bwd_iat_max = 0.0
            init_bwd_win_bytes = 0

        features = {
            'Pkt Size Avg': pkt_size_avg,
            'Pkt Len Max': pkt_len_max,
            'Pkt Len Mean': pkt_len_mean,
            'SYN Flag Cnt': syn_flag_cnt,
            'Bwd IAT Tot': bwd_iat_tot,
            'Init Bwd Win Byts': init_bwd_win_bytes,
            'Dst Port': dst_port,
            'Bwd Header Len': bwd_header_len,
            'Fwd Pkt Len Min': fwd_pkt_len_min,
            'Tot Bwd Pkts': tot_bwd_pkts,
            'Bwd IAT Max': bwd_iat_max,
            'Fwd Pkt Len Max': fwd_pkt_len_max
        }

        # Debug log of raw features
        try:
            feature_str = ", ".join(f"{k}={v}" for k, v in features.items())
            log.debug("Raw feature dict: %s", feature_str)
        except Exception as e:
            log.warning("Failed to format feature log: %s", e)

        # Build ordered feature vector
        feature_vector = np.array([features[f] for f in self.feature_names]).reshape(1, -1)
        log.debug("Feature vector (ordered): %s", feature_vector)
        return feature_vector

    # -----------------------------------------------------------------------
    # Risk calculation using the ML model
    # -----------------------------------------------------------------------
    def _calculate_risk(self, features):
        """Scale features and compute risk score using the XGBoost model."""
        try:
            features_scaled = self.scaler.transform(features)
            log.debug("Scaled features: %s", features_scaled[0])

            probs = self.model.predict_proba(features_scaled)[0]
            log.debug("Model predict_proba output: %s", probs)

            if self.attack_class_index is None:
                log.error("attack_class_index is None, cannot compute risk properly. Returning 0.")
                return 0.0

            attack_prob = probs[self.attack_class_index]
            risk_score = float(attack_prob * 100.0)

            log.debug("Using attack_class_index=%d -> attack_prob=%.4f, risk_score=%.2f",
                      self.attack_class_index, attack_prob, risk_score)
            return risk_score

        except Exception as e:
            log.error("Error calculating risk: %s", e)
            return 0.0

    # -----------------------------------------------------------------------
    # Blocking logic
    # -----------------------------------------------------------------------
    def _block_host(self, mac_address):
        """Install drop rules on all switches for the given MAC address."""
        if mac_address in self.blocked_hosts:
            log.info("Host %s is already blocked", mac_address)
            return

        log.warning("⛔ BLOCKING host %s across all switches", mac_address)
        self.blocked_hosts.add(mac_address)

        for dpid, connection in self.connections.items():
            msg = of.ofp_flow_mod()
            msg.match.dl_src = EthAddr(mac_address)
            msg.priority = 100
            msg.hard_timeout = 300  # Block for 5 minutes
            # No actions = drop
            connection.send(msg)
            log.info("  └─ Drop rule installed on switch %s", dpid_to_str(dpid))


def launch():
    """POX launch function."""
    core.registerNew(BehavioralAuthController)
