#include <core.p4>
#include <v1model.p4>

// ====================== Constants ======================

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8>  IP_PROTO_TCP   = 6;
const bit<8>  IP_PROTO_UDP   = 17;

const bit<32> MAX_FLOWS = 1024;

// ====================== Headers ========================

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

// Feature reporting header (for packets cloned to CPU)
header cpu_metadata_t {
    bit<32> flow_id;
    bit<32> packet_count;
    bit<32> byte_count;
    bit<48> iat_sum;      // Inter-arrival time sum
    bit<32> avg_pkt_size; // Filled as 0 in data plane; compute in controller
    bit<32> risk_score;   // Placeholder, controller can update
}

// ====================== Structs ========================

struct headers {
    ethernet_t     ethernet;
    ipv4_t         ipv4;
    tcp_t          tcp;
    udp_t          udp;
    cpu_metadata_t cpu_metadata;
}

// Note: @field_list(1) tells v1model which metadata fields to copy
// when using clone_preserving_field_list(..., 1)
struct metadata {
    @field_list(1) bit<32> flow_id;
    bit<32>               flow_hash;

    bit<48> last_packet_time;
    bit<48> current_time;
    bit<48> iat;

    @field_list(1) bit<32> packet_count;
    @field_list(1) bit<32> byte_count;
    @field_list(1) bit<48> iat_sum;
}

// ====================== Parser =========================

parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default:        accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default:      accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

// ====================== Registers ======================
// Per-flow state (indexed by hashed flow id)

register<bit<32>>(MAX_FLOWS) flow_packet_count;
register<bit<32>>(MAX_FLOWS) flow_byte_count;
register<bit<48>>(MAX_FLOWS) flow_last_timestamp;
register<bit<48>>(MAX_FLOWS) flow_iat_sum;

// ====================== Ingress ========================

control MyIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    // --------- Actions ----------

    // Compute flow hash (5-tuple)
    action compute_flow_hash() {
        hash(meta.flow_hash,
             HashAlgorithm.crc32,
             (bit<32>)0,
             { hdr.ipv4.srcAddr,
               hdr.ipv4.dstAddr,
               hdr.tcp.isValid() ? hdr.tcp.srcPort : (bit<16>)0,
               hdr.tcp.isValid() ? hdr.tcp.dstPort : (bit<16>)0,
               hdr.ipv4.protocol },
             MAX_FLOWS);
        meta.flow_id = meta.flow_hash;
    }

    // Extract / update features in registers
    action extract_and_update_features() {
        bit<48> current_ts = standard_metadata.ingress_global_timestamp;
        bit<48> last_ts;
        bit<48> iat;
        bit<32> pkt_cnt;
        bit<32> byte_cnt;
        bit<48> iat_s;

        // Read current state
        flow_last_timestamp.read(last_ts, meta.flow_id);
        flow_packet_count.read(pkt_cnt, meta.flow_id);
        flow_byte_count.read(byte_cnt, meta.flow_id);
        flow_iat_sum.read(iat_s, meta.flow_id);

        // Calculate IAT (if last_ts = 0, first packet -> iat = 0)
        iat = (last_ts == 0) ? (bit<48>)0 : (current_ts - last_ts);

        // Update registers
        flow_last_timestamp.write(meta.flow_id, current_ts);
        flow_packet_count.write(meta.flow_id, pkt_cnt + 1);
        flow_byte_count.write(
            meta.flow_id,
            byte_cnt + (bit<32>)standard_metadata.packet_length
        );
        flow_iat_sum.write(meta.flow_id, iat_s + iat);

        // Store in metadata for egress / clone
        meta.current_time      = current_ts;
        meta.last_packet_time  = last_ts;
        meta.iat               = iat;
        meta.packet_count      = pkt_cnt + 1;
        meta.byte_count        =
            byte_cnt + (bit<32>)standard_metadata.packet_length;
        meta.iat_sum           = iat_s + iat;
    }

    // Clone packet to CPU (digest-like export)
    action send_feature_digest() {
        // Use clone_preserving_field_list to keep annotated metadata fields
        // You must configure:  mirroring_add 999 <cpu_port>  in simple_switch_CLI
        clone_preserving_field_list(CloneType.I2E, 999, (bit<8>)1);
    }

    action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    // --------- Tables ----------

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;
            drop;
            NoAction;
        }
        default_action = drop();
    }

    // --------- Apply ----------

    apply {
        if (hdr.ipv4.isValid() &&
            (hdr.tcp.isValid() || hdr.udp.isValid())) {

            compute_flow_hash();
            extract_and_update_features();

            // For now, send features to CPU on *every* such packet.
            // (You can later add rate limiting in the control plane.)
            send_feature_digest();
        }

        // Normal forwarding
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

// ====================== Egress =========================

control MyEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    apply {
        // In v1model / simple_switch:
        // PKT_INSTANCE_TYPE_INGRESS_CLONE = 1
        if (standard_metadata.instance_type == 1) {
            hdr.cpu_metadata.setValid();
            hdr.cpu_metadata.flow_id       = meta.flow_id;
            hdr.cpu_metadata.packet_count  = meta.packet_count;
            hdr.cpu_metadata.byte_count    = meta.byte_count;
            hdr.cpu_metadata.iat_sum       = meta.iat_sum;

            // avg_pkt_size: compute in controller; set 0 in data plane
            hdr.cpu_metadata.avg_pkt_size  = (bit<32>)0;
            hdr.cpu_metadata.risk_score    = (bit<32>)0; // placeholder
        }
    }
}

// ====================== Checksum =======================

control MyComputeChecksum(
    inout headers hdr,
    inout metadata meta
) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control MyVerifyChecksum(
    inout headers hdr,
    inout metadata meta
) {
    apply {
        // Optionally verify IPv4 checksum here; left empty for simplicity.
    }
}

// ====================== Deparser =======================
// NOTE: no if-statements here – your backend doesn't support them in deparser.

control MyDeparser(
    packet_out packet,
    in headers hdr
) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.cpu_metadata);
    }
}

// ====================== Main ===========================

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
