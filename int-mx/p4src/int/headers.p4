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

const bit<6> HW_ID = 1;

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  IP_PROTO_UDP = 0x11;
const bit<8>  IP_PROTO_TCP = 0x6;
const bit<16> INT_PORT = 5000; 
const bit<16> SHIM_LEN = 12; 

const bit<6> DSCP_INT = 0x17;
const bit<6> DSCP_MASK = 0x3F;

typedef bit<48> mac_t;
typedef bit<32> ip_address_t;
typedef bit<16> l4_port_t;
typedef bit<9>  port_t;

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
    bit<4> int_type;                // Type of INT Header
    bit<2> npt;                     // Next protocol type
    bit<2> rsvd;                    // Reserved
    bit<8> len;                     // Length of INT Metadata header and INT stack in 4-byte words, not including the shim header (1 word)
    bit<6> udp_ip_dscp;            // depends on npt field. either original dscp, ip protocol or udp dest port
    bit<10> udp_ip;                // depends on npt field. either original dscp, ip protocol or udp dest port
}

const bit<16> INT_SHIM_HEADER_SIZE = 4;

// INT header
header int_header_t {
    bit<4>   ver;                    // Version
    bit<1>   d;                      // Discard
    bit<27>  rsvd;                   // 12 bits reserved, set to 0                  
    bit<4>   instruction_mask_0003;  /* split the bits for lookup */
    bit<4>   instruction_mask_0407;
    bit<4>   instruction_mask_0811;
    bit<4>   instruction_mask_1215;
    bit<16>  domain_specific_id;     // Unique INT Domain ID
    bit<16>  ds_instruction;         // Instruction bitmap specific to the INT Domain identified by the Domain specific ID
    bit<16>  ds_flags;               // Domain specific flags
    // Optional domain specific 'source only' metadata
}

const bit<16> INT_HEADER_SIZE = 12;

const bit<16> INT_TOTAL_HEADER_SIZE = 16; // 12 + 4 


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
    bit<64> ingress_tstamp;
}
header int_egress_tstamp_t {
    bit<64> egress_tstamp;
}
header int_level2_port_ids_t {
    bit<32> ingress_port_id;
    bit<32> egress_port_id;
}

// these two not implemented yet
header int_egress_port_tx_util_t {
    bit<32> egress_port_tx_util;
}
header int_buffer_t {
    bit<8> buffer_id;
    bit<24> buffer_occupancy;
}

// Report Telemetry Headers
header report_group_header_t {
    bit<4>  ver;
    bit<6>  hw_id;
    bit<22> seq_no;
    bit<32> node_id;
}
const bit<8> REPORT_GROUP_HEADER_LEN = 8;

header report_individual_header_t {
    bit<4>  rep_type;
    bit<4>  in_type;
    bit<8>  len;
    bit<8>  rep_md_len;
    bit<1>  d;
    bit<1>  q;
    bit<1>  f;
    bit<1>  i;
    bit<4>  rsvd;
    // Individual report inner contents for Reptype 1 = INT
    bit<16> rep_md_bits;
    bit<16> domain_specific_id;
    bit<16> domain_specific_md_bits;
    bit<16> domain_specific_md_status;
}
const bit<8> REPORT_INDIVIDUAL_HEADER_LEN = 12;

// Telemetry drop report header
header drop_report_header_t {
    bit<32> switch_id;
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
    bit<8>  queue_id;
    bit<8>  drop_reason;
    bit<16> pad;
}
const bit<8> DROP_REPORT_HEADER_LEN = 12;

// Switch Local Report Header
header local_report_header_t {
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
    bit<8>  queue_id;
    bit<8>  pad;
    bit<64> ingress_global_tstamp;
}

const bit<8> LOCAL_REPORT_HEADER_LEN = 16;

header mirror_h {
    pkt_type_t  pkt_type;
    bit<16> ingress_port_id;
    bit<16> egress_port_id;
    bit<8>  queue_id;
    bit<64> ingress_global_tstamp;

    bit<4> int_type;                // Type of INT Header
    bit<2> npt;                     // Next protocol type
    bit<2> int_l4_rsvd;                    // Reserved
    bit<8> len;                     // Length of INT Metadata header and INT stack in 4-byte words, not including the shim header (1 word)
    bit<6> udp_ip_dscp;            // depends on npt field. either original dscp, ip protocol or udp dest port
    bit<10> udp_ip;                // depends on npt field. either original dscp, ip protocol or udp dest port

    bit<4>   ver;                    // Version
    bit<1>   d;                      // Discard
    bit<27>  rsvd;                   // 12 bits reserved, set to 0                  
    bit<4>   instruction_mask_0003;  /* split the bits for lookup */
    bit<4>   instruction_mask_0407;
    bit<4>   instruction_mask_0811;
    bit<4>   instruction_mask_1215;
    bit<16>  domain_specific_id;     // Unique INT Domain ID
    bit<16>  ds_instruction;         // Instruction bitmap specific to the INT Domain identified by the Domain specific ID
    bit<16>  ds_flags;               // Domain specific flags
    // Optional domain specific 'source only' metadata
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
    int_switch_id_t             int_switch_id;
    int_level1_port_ids_t       int_level1_port_ids;
    int_hop_latency_t           int_hop_latency;
    int_q_occupancy_t           int_q_occupancy;
    int_ingress_tstamp_t        int_ingress_tstamp;
    int_egress_tstamp_t         int_egress_tstamp;
    int_level2_port_ids_t       int_level2_port_ids;
    int_egress_port_tx_util_t   int_egress_tx_util;

    // // INT Report Headers
    report_group_header_t       report_group_header;
    report_individual_header_t  report_individual_header;
    local_report_header_t       local_report_header;

    mirror_h                    mirror_header;
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
    bool  sink;
    pkt_type_t pkt_type;
    MirrorId_t ing_mir_ses;   // Ingress mirror session ID
    MirrorId_t egr_mir_ses;   // Egress mirror session ID
}