/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

#define MAX_INT_HEADERS 9
#define MAX_HOP_COUNT 3
#define NUM_INSTRUCTIONS 3

#define ETH_TYPE_IPV4 0x0800
#define IP_VERSION_4 4w4
#define MAX_PORTS 511
#define IPV4_IHL_MIN 4w5

#ifndef _BOOL
#define _BOOL bool
#endif
#ifndef _TRUE
#define _TRUE true
#endif
#ifndef _FALSE
#define _FALSE false
#endif

// 1 --> 2 --> 3 Switch hardware ID. This has to be changed depending on the switch
const bit<6> HW_ID = 1;

// Make this dynamic depending on UDP/IP Header
// This field determines the size of the payload (in bits) that is skipped in order to send telemetry reports without payload data
const bit<32> PACKET_ADVANCE = 40;

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  IP_PROTO_UDP = 0x11;
const bit<8>  IP_PROTO_TCP = 0x6;
const bit<16> INT_PORT = 5000; 

// These fields need to be made dependent on values in the INT header to determine the length of the packet
const bit<16> SHIM_LEN = 84; // SHIM LEN is INT_DATA_LEN - 8. Change for different bitmap. for 64 bits -> 28
const bit<16> INT_DATA_LEN = 120; // SHIM LEN + 8 for 64 bits -> 36

const bit<6> DSCP_INT = 0x17;
const bit<6> DSCP_MASK = 0x3F;
const bit<8> HOP_1 = 0x1A;
const bit<8> HOP_2 = 0xC;
const bit<6> DSCP_IP = 0x5c;

typedef bit<48> mac_t;
typedef bit<32> ip_address_t;
typedef bit<16> l4_port_t;
typedef bit<9>  port_t;
typedef bit<16> next_hop_id_t;

const bit<8> INT_HEADER_LEN_WORD = 3;
const bit<8> REPORT_HDR_TTL = 64;
const port_t CPU_PORT = 255;

const bit<3> NPROTO_ETHERNET = 0;
const bit<3> NPROTO_TELEMETRY_DROP_HEADER = 1;
const bit<3> NPROTO_TELEMETRY_SWITCH_LOCAL_HEADER = 2;

const bit<5>  IPV4_OPTION_INT = 31;

// Mirroring defs
typedef bit<3> mirror_type_t;
typedef bit<8>  pkt_type_t;

const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;
const pkt_type_t PKT_TYPE_NORMAL = 1;
const pkt_type_t PKT_TYPE_MIRROR = 2;

typedef bit<32> switch_id_t;
typedef bit<48> timestamp_t;
typedef bit<6>  output_port_t;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

const bit<8> ETH_HEADER_LEN = 14;

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

const bit<8> IPV4_MIN_HEAD_LEN = 20;


header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length_;
    bit<16> checksum;
}
const bit<8> UDP_HEADER_LEN = 8;


header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

const bit<8> TCP_HEADER_LEN = 20;

// INT shim header for TCP/UDP
header intl4_shim_t {
    bit<8> int_type;
    bit<8> rsvd1;
    bit<8> len;
    bit<6> dscp;
    bit<2> rsvd2;
}

const bit<16> INT_SHIM_HEADER_SIZE = 4;

// INT header
header int_header_t {
    bit<4>  ver;
    bit<2>  rep;
    bit<1>  c;
    bit<1>  e;
    bit<1>  m;
    bit<7>  rsvd1;
    bit<3>  rsvd2;
    bit<5>  hop_metadata_len;
    bit<8>  remaining_hop_cnt;
    bit<4>  instruction_mask_0003; /* split the bits for lookup */
    bit<4>  instruction_mask_0407;
    bit<4>  instruction_mask_0811;
    bit<4>  instruction_mask_1215;
    bit<16> rsvd3;
}

const bit<16> INT_HEADER_SIZE = 8;

const bit<16> INT_TOTAL_HEADER_SIZE = INT_HEADER_SIZE + INT_SHIM_HEADER_SIZE;


// INT meta-value headers - different header for each value type
header int_switch_id_t {
    bit<32> switch_id;
}
header int_level1_port_ids_t {
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
}
header int_hop_latency_t {
    bit<32> hop_latency;
}
header int_q_occupancy_t {
    bit<8> q_id;
    bit<24> q_occupancy;
}
header int_ingress_tstamp_t {
    bit<32> ingress_tstamp;
}
header int_egress_tstamp_t {
    bit<32> egress_tstamp;
}
header int_level2_port_ids_t {
    bit<32> ingress_port_id;
    bit<32> egress_port_id;
}
header int_egress_port_tx_util_t { // queueing latency
    bit<32> egress_port_tx_util;
}

header int_data_t {
    // varbit data; 
    // change this depending on the INT data embedded, 576 = 2 hops of all metadata. 128 = 2 hops of 64 bit metadata.
    // 8 --> 288 --> 576
    // currently this is only needed for the last switch to extract necessary int metadata
    bit<576> data;
}


// Report Telemetry Headers
header report_fixed_header_t {
    bit<4>  ver;
    bit<4>  len;
    bit<3>  nproto;
    bit<6>  rep_md_bits;
    bit<6>  rsvd;
    bit<3>  d_q_f;
    bit<6>  hw_id;
    bit<32> sw_id;
    bit<32> seq_no;
    bit<32> ingress_tstamp;
}
const bit<8> REPORT_FIXED_HEADER_LEN = 16;

// Switch Local Report Header
header local_report_header_t {
    bit<32> switch_id;
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
    bit<32>  queue_id;
    bit<24> queue_occupancy;
    //bit<32> egress_tstamp;
    bit<48> ingress_global_tstamp;
    bool sink;
    bool do_report;
    bit<6> pad;
    pkt_type_t  pkt_type;
    bit<16> int_shim_len;
}
const bit<8> LOCAL_REPORT_HEADER_LEN = 16;

header mirror_h {
    pkt_type_t  pkt_type;
    bit<16> ingress_port_id;
    bit<32>  queue_id;
    bit<48> ingress_global_tstamp;
}

struct headers {

    // Original Packet Headers
    ethernet_t                  ethernet;
    ipv4_t			            ipv4;
    udp_t			            udp;
    tcp_t			            tcp;

    // INT Report Encapsulation
    ethernet_t                  report_ethernet;
    ipv4_t                      report_ipv4;
    udp_t                       report_udp;

    // INT Headers
    int_header_t                int_header;
    intl4_shim_t                intl4_shim;
    int_data_t                  int_data;
    int_switch_id_t             int_switch_id;
    int_level1_port_ids_t       int_level1_port_ids;
    int_hop_latency_t           int_hop_latency;
    int_q_occupancy_t           int_q_occupancy;
    int_ingress_tstamp_t        int_ingress_tstamp;
    int_egress_tstamp_t         int_egress_tstamp;
    int_level2_port_ids_t       int_level2_port_ids;
    int_egress_port_tx_util_t   int_egress_tx_util;

    // // INT Report Headers
    report_fixed_header_t       report_fixed_header;
    local_report_header_t       local_report_header;

    mirror_h                       mirror_header;
}

struct int_metadata_t {
    switch_id_t switch_id;
    bit<16> new_bytes;
    bit<8>  new_words;
    bool  source;
    bool  sink;
    bool  transit;
    bit<8> intl4_shim_len;
    bit<16> int_shim_len;
}

struct local_metadata_t {
    bit<16>       l4_src_port;
    bit<16>       l4_dst_port;
    int_metadata_t int_meta;
    bool  mirror;
    pkt_type_t pkt_type;
    MirrorId_t ing_mir_ses;   // Ingress mirror session ID
    MirrorId_t egr_mir_ses;   // Egress mirror session ID
}
