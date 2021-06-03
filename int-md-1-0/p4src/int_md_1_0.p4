/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * This file has been modified. 
 * Modifications Copyright © 2021 Saab AB / Mandar Joshi
 */

/*
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

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

// 1 --> 2 --> 3 Switch hardware ID
const bit<6> HW_ID = 1;

// Make this dynamic depending on UDP/IP Header
const bit<32> PACKET_ADVANCE = 40;

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  IP_PROTO_UDP = 0x11;
const bit<8>  IP_PROTO_TCP = 0x6;
const bit<16> INT_PORT = 5000; 
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
    bool  sink;
    pkt_type_t pkt_type;
    MirrorId_t ing_mir_ses;   // Ingress mirror session ID
    MirrorId_t egr_mir_ses;   // Egress mirror session ID
}

/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/

parser MyIngressParser(packet_in packet,
                        out headers hdr,
                        out local_metadata_t local_metadata,
                        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;
        transition select(hdr.ipv4.dscp) {
            DSCP_INT &&& DSCP_MASK: parse_shim;
            default:  accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition select(hdr.ipv4.dscp) {
            DSCP_INT &&& DSCP_MASK: parse_shim;
            default:  accept;
        }
    }

    state parse_shim {
        packet.extract(hdr.intl4_shim);
        transition parse_int_hdr;
    }

    state parse_int_hdr {
        packet.extract(hdr.int_header);
        transition parse_int_data;
    }

    state parse_int_data {
        //, ((bit<32>) (local_metadata.int_meta.intl4_shim_len - INT_HEADER_LEN_WORD)) << 5
        // because of int data from previous switches
        // bit<8> int_hdr_len_in_words = (bit<8>)(INT_TOTAL_HEADER_SIZE)>>2;
        // bit<32> int_data_len_in_words = (bit<32>)(hdr.intl4_shim.len - int_hdr_len_in_words);
        // bit<32> int_data_len_in_bits = int_data_len_in_words << 5;
        // , ((bit<32>)(hdr.intl4_shim.len - (bit<8>)(INT_TOTAL_HEADER_SIZE)>>2) << 5)

        //packet.extract(hdr.int_data);
        transition accept;
    }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control port_forward(inout headers hdr,
                       inout local_metadata_t local_metadata,
                       inout ingress_intrinsic_metadata_for_tm_t ig_tm_md,
                       inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    action send_to_cpu() {
        ig_tm_md.ucast_egress_port = CPU_PORT;
    }

    action set_egress_port(port_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    table tb_port_forward {
        key = {
            hdr.ipv4.dst_addr              : lpm;
        }
        actions = {
            set_egress_port;
            send_to_cpu;
            drop;
        }
        const default_action = drop();
    }

    apply {
        tb_port_forward.apply();
     }
}

control process_int_source_sink (
    inout headers hdr,
    inout local_metadata_t local_metadata,
    in ingress_intrinsic_metadata_t ig_intr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action int_set_source () {
        local_metadata.int_meta.source = _TRUE;
    }

    action int_set_sink () {
        local_metadata.int_meta.sink = _TRUE;
    }

    table tb_set_source {
        key = {
            ig_intr_md.ingress_port: exact;
        }
        actions = {
            int_set_source;
            NoAction();
        }
        const default_action = NoAction();
        size = MAX_PORTS;
    }
    table tb_set_sink {
        key = {
            ig_tm_md.ucast_egress_port: exact;
        }
        actions = {
            int_set_sink;
            NoAction();
        }
        const default_action = NoAction();
        size = MAX_PORTS;
    }

    apply {
        tb_set_source.apply();
        tb_set_sink.apply();
    }
}

// Insert INT header to the packet
control process_int_source (
    inout headers hdr,
    inout local_metadata_t local_metadata) {

    action int_source(bit<5> hop_metadata_len, bit<8> remaining_hop_cnt, bit<4> ins_mask0003, bit<4> ins_mask0407) {
        // insert INT shim header
        hdr.intl4_shim.setValid();
        // int_type: Hop-by-hop type (1) , destination type (2)
        hdr.intl4_shim.int_type = 1;
        hdr.intl4_shim.len = INT_HEADER_LEN_WORD; // This is 3 from 0xC (INT_TOTAL_HEADER_SIZE >> 2)
        hdr.intl4_shim.dscp = hdr.ipv4.dscp;

        // insert INT header
        hdr.int_header.setValid();
        hdr.int_header.ver = 1;
        hdr.int_header.rep = 0;
        hdr.int_header.c = 0;
        hdr.int_header.e = 0;
        hdr.int_header.m = 0;
        hdr.int_header.rsvd1 = 0;
        hdr.int_header.rsvd2 = 0;
        hdr.int_header.hop_metadata_len = hop_metadata_len;
        hdr.int_header.remaining_hop_cnt = remaining_hop_cnt;
        hdr.int_header.instruction_mask_0003 = ins_mask0003;
        hdr.int_header.instruction_mask_0407 = ins_mask0407;
        hdr.int_header.instruction_mask_0811 = 0; // not supported
        hdr.int_header.instruction_mask_1215 = 0; // not supported

        // add the header len (3 words) to total len
        hdr.ipv4.len = hdr.ipv4.len + INT_TOTAL_HEADER_SIZE;
        hdr.udp.length_ = hdr.udp.length_ + INT_TOTAL_HEADER_SIZE;
    }

    action int_source_dscp(bit<5> hop_metadata_len, bit<8> remaining_hop_cnt, bit<4> ins_mask0003, bit<4> ins_mask0407) {
        int_source(hop_metadata_len, remaining_hop_cnt, ins_mask0003, ins_mask0407);
        hdr.ipv4.dscp = DSCP_INT;
    }

    table tb_int_source {
        key = {
            //configure for each flow to be monitored
            // 4 fields identifying flow
            //include ip src, udp/tcp src and dest too
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            int_source_dscp;
            NoAction;
        }
        const default_action = NoAction();
    }

    apply {
        tb_int_source.apply();
    }
}

control process_set_sink (
    inout headers hdr,
    inout local_metadata_t local_metadata,
    in egress_intrinsic_metadata_t eg_intr_md) {

    action int_set_sink () {
        local_metadata.int_meta.sink = _TRUE;
    }

    table tb_set_sink {
        key = {
            eg_intr_md.egress_port: exact;
        }
        actions = {
            int_set_sink;
            NoAction();
        }
        const default_action = NoAction();
        size = MAX_PORTS;
    }

    apply {
        tb_set_sink.apply();
    }
}

control process_int_transit (
    inout headers hdr,
    inout local_metadata_t local_metadata,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_prsr_md) {

    action init_metadata(switch_id_t switch_id) {
        local_metadata.int_meta.transit = _TRUE;
        local_metadata.int_meta.switch_id = switch_id;
    }

    
    action int_set_header_0() { //switch_id
        hdr.int_switch_id.setValid();
        hdr.int_switch_id.switch_id = local_metadata.int_meta.switch_id;
    }
    
    action int_set_header_1() { //level1_port_id - physical port
        hdr.int_level1_port_ids.setValid();
        hdr.int_level1_port_ids.ingress_port_id =
        (bit<16>) hdr.local_report_header.ingress_port_id;
        hdr.int_level1_port_ids.egress_port_id = (bit<16>) eg_intr_md.egress_port;
    }
    
    action int_set_header_2() { //hop_latency
        hdr.int_hop_latency.setValid();
        hdr.int_hop_latency.hop_latency = (bit<32>) (eg_prsr_md.global_tstamp - 
        hdr.local_report_header.ingress_global_tstamp);
    }
    
    action int_set_header_3() { //q_occupancy
        hdr.int_q_occupancy.setValid();
        hdr.int_q_occupancy.q_id =
        (bit<8>) hdr.local_report_header.queue_id;
        hdr.int_q_occupancy.q_occupancy =
        (bit<24>) eg_intr_md.deq_qdepth;
    }
    
    action int_set_header_4() { //ingress_tstamp
        hdr.int_ingress_tstamp.setValid();
        hdr.int_ingress_tstamp.ingress_tstamp =
        (bit<32>) hdr.local_report_header.ingress_global_tstamp;
    }
    
    action int_set_header_5() { //egress_timestamp
        hdr.int_egress_tstamp.setValid();
        hdr.int_egress_tstamp.egress_tstamp =
        (bit<32>) eg_prsr_md.global_tstamp;
    }
    
    action int_set_header_6() { //level2_port_id
        hdr.int_level2_port_ids.setValid();
        // level2_port_id indicates Logical port ID - update this!
        hdr.int_level2_port_ids.ingress_port_id = (bit<32>) local_metadata.l4_src_port;
        hdr.int_level2_port_ids.egress_port_id = (bit<32>) local_metadata.l4_dst_port;
     }
    
    action int_set_header_7() { // queueing latency
        hdr.int_egress_tx_util.setValid();
        hdr.int_egress_tx_util.egress_port_tx_util =
        (bit<32>) eg_intr_md.deq_timedelta;
    }

    // Actions to keep track of the new metadata added.
    
    action add_1() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 1;
        local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 4;
    }

    
    action add_2() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 2;
        local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 8;
    }

    
    action add_3() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 3;
        local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 12;
    }

    
    action add_4() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 4;
       local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 16;
    }

    
    action add_5() {
        local_metadata.int_meta.new_words = local_metadata.int_meta.new_words + 5;
        local_metadata.int_meta.new_bytes = local_metadata.int_meta.new_bytes + 20;
    }

     /* action function for bits 0-3 combinations, 0 is msb, 3 is lsb */
     /* Each bit set indicates that corresponding INT header should be added */
    
     action int_set_header_0003_i0() {
     }
    
     action int_set_header_0003_i1() {
        int_set_header_3();
        add_1();
    }
    
    action int_set_header_0003_i2() {
        int_set_header_2();
        add_1();
    }
    
    action int_set_header_0003_i3() {
        int_set_header_3();
        int_set_header_2();
        add_2();
    }
    
    action int_set_header_0003_i4() {
        int_set_header_1();
        add_1();
    }
    
    action int_set_header_0003_i5() {
        int_set_header_3();
        int_set_header_1();
        add_2();
    }
    
    action int_set_header_0003_i6() {
        int_set_header_2();
        int_set_header_1();
        add_2();
    }
    
    action int_set_header_0003_i7() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        add_3();
    }
    
    action int_set_header_0003_i8() {
        int_set_header_0();
        add_1();
    }
    
    action int_set_header_0003_i9() {
        int_set_header_3();
        int_set_header_0();
        add_2();
    }
    
    action int_set_header_0003_i10() {
        int_set_header_2();
        int_set_header_0();
        add_2();
    }
    
    action int_set_header_0003_i11() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_0();
        add_3();
    }
    
    action int_set_header_0003_i12() {
        int_set_header_1();
        int_set_header_0();
        add_2();
    }
    
    action int_set_header_0003_i13() {
        int_set_header_3();
        int_set_header_1();
        int_set_header_0();
        add_3();
    }
    
    action int_set_header_0003_i14() {
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
        add_3();
    }
    
    action int_set_header_0003_i15() {
        int_set_header_3();
        int_set_header_2();
        int_set_header_1();
        int_set_header_0();
        add_4();
    }

    /* action function for bits 4-7 combinations, 4 is msb, 7 is lsb */
    
    action int_set_header_0407_i0() {
    }
    
    action int_set_header_0407_i1() {
        int_set_header_7();
        add_1();
    }
    
    action int_set_header_0407_i2() {
        int_set_header_6();
        add_2();
    }
    
    action int_set_header_0407_i3() {
        int_set_header_7();
        int_set_header_6();
        add_3();
    }
    
    action int_set_header_0407_i4() {
        int_set_header_5();
        add_1();
    }
    
    action int_set_header_0407_i5() {
        int_set_header_7();
        int_set_header_5();
        add_2();
    }
    
    action int_set_header_0407_i6() {
        int_set_header_6();
        int_set_header_5();
        add_3();
    }
    
    action int_set_header_0407_i7() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
        add_4();
    }
    
    action int_set_header_0407_i8() {
        int_set_header_4();
        add_1();
    }
    
    action int_set_header_0407_i9() {
        int_set_header_7();
        int_set_header_4();
        add_2();
    }
    
    action int_set_header_0407_i10() {
        int_set_header_6();
        int_set_header_4();
        add_3();
    }
    
    action int_set_header_0407_i11() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_4();
        add_4();
    }
    
    action int_set_header_0407_i12() {
        int_set_header_5();
        int_set_header_4();
        add_2();
    }
    
    action int_set_header_0407_i13() {
        int_set_header_7();
        int_set_header_5();
        int_set_header_4();
        add_3();
    }
    
    action int_set_header_0407_i14() {
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
        add_4();
    }
    
    action int_set_header_0407_i15() {
        int_set_header_7();
        int_set_header_6();
        int_set_header_5();
        int_set_header_4();
        add_5();
    }

    // Default action used to set switch ID.
    table tb_int_insert {
        // key = {
        // }
        actions = {
            init_metadata;
            NoAction;
        }
        default_action = NoAction();
        size = 1;
    }

    /* Table to process instruction bits 0-3 */
    
    table tb_int_inst_0003 {
        key = {
            hdr.int_header.instruction_mask_0003 : exact;
        }
        actions = {
            int_set_header_0003_i0;
            int_set_header_0003_i1;
            int_set_header_0003_i2;
            int_set_header_0003_i3;
            int_set_header_0003_i4;
            int_set_header_0003_i5;
            int_set_header_0003_i6;
            int_set_header_0003_i7;
            int_set_header_0003_i8;
            int_set_header_0003_i9;
            int_set_header_0003_i10;
            int_set_header_0003_i11;
            int_set_header_0003_i12;
            int_set_header_0003_i13;
            int_set_header_0003_i14;
            int_set_header_0003_i15;
        }
        
        const entries = {
            (0x0) : int_set_header_0003_i0();
            (0x1) : int_set_header_0003_i1();
            (0x2) : int_set_header_0003_i2();
            (0x3) : int_set_header_0003_i3();
            (0x4) : int_set_header_0003_i4();
            (0x5) : int_set_header_0003_i5();
            (0x6) : int_set_header_0003_i6();
            (0x7) : int_set_header_0003_i7();
            (0x8) : int_set_header_0003_i8();
            (0x9) : int_set_header_0003_i9();
            (0xA) : int_set_header_0003_i10();
            (0xB) : int_set_header_0003_i11();
            (0xC) : int_set_header_0003_i12();
            (0xD) : int_set_header_0003_i13();
            (0xE) : int_set_header_0003_i14();
            (0xF) : int_set_header_0003_i15();
        }
        size = 16;
    }

    /* Table to process instruction bits 4-7 */
    
    table tb_int_inst_0407 {
        key = {
            hdr.int_header.instruction_mask_0407 : exact;
        }
        actions = {
            int_set_header_0407_i0;
            int_set_header_0407_i1;
            int_set_header_0407_i2;
            int_set_header_0407_i3;
            int_set_header_0407_i4;
            int_set_header_0407_i5;
            int_set_header_0407_i6;
            int_set_header_0407_i7;
            int_set_header_0407_i8;
            int_set_header_0407_i9;
            int_set_header_0407_i10;
            int_set_header_0407_i11;
            int_set_header_0407_i12;
            int_set_header_0407_i13;
            int_set_header_0407_i14;
            int_set_header_0407_i15;
        }
        
        const entries = {
            (0x0) : int_set_header_0407_i0();
            (0x1) : int_set_header_0407_i1();
            (0x2) : int_set_header_0407_i2();
            (0x3) : int_set_header_0407_i3();
            (0x4) : int_set_header_0407_i4();
            (0x5) : int_set_header_0407_i5();
            (0x6) : int_set_header_0407_i6();
            (0x7) : int_set_header_0407_i7();
            (0x8) : int_set_header_0407_i8();
            (0x9) : int_set_header_0407_i9();
            (0xA) : int_set_header_0407_i10();
            (0xB) : int_set_header_0407_i11();
            (0xC) : int_set_header_0407_i12();
            (0xD) : int_set_header_0407_i13();
            (0xE) : int_set_header_0407_i14();
            (0xF) : int_set_header_0407_i15();
        }
        size = 16;
    }

    apply {
        tb_int_insert.apply();
        if (local_metadata.int_meta.transit == _FALSE) {
            return;
        }
        tb_int_inst_0003.apply();
        tb_int_inst_0407.apply();

        // Decrement remaining hop cnt
        hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt - 1;

        // Update headers lengths.
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.len = hdr.ipv4.len + local_metadata.int_meta.new_bytes;
        }
        if (hdr.udp.isValid()) {
            hdr.udp.length_ = hdr.udp.length_ + local_metadata.int_meta.new_bytes;
        }
        if (hdr.intl4_shim.isValid()) {
            // 9 words if add 4 + add 5
            hdr.intl4_shim.len = hdr.intl4_shim.len + local_metadata.int_meta.new_words;
        }
    }
}

control process_int_sink (
    inout headers hdr,
    inout local_metadata_t local_metadata) {
    
    action restore_header () {
        hdr.ipv4.dscp = hdr.intl4_shim.dscp;
        hdr.ipv4.len = hdr.ipv4.len - SHIM_LEN;
        hdr.udp.length_ = hdr.udp.length_ - SHIM_LEN;
        
    }

    
    action int_sink() {
        // remove all the INT information from the packet
        hdr.int_header.setInvalid();
        hdr.int_data.setInvalid();
        hdr.intl4_shim.setInvalid();
    }

    apply {
        restore_header();
        int_sink();
    }
}

control process_int_report (
    inout headers hdr,
    inout local_metadata_t local_metadata,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_prsr_md) {

    // Register for sequence number
    Register<bit<32>, _>(1) counter;
    RegisterAction<bit<32>, _, bit<32>>(counter) counter_incr = {
        void apply(inout bit<32> value, out bit<32> read_value){
            bit<32> in_value = value;
            value = in_value + 1;
            read_value = value;
        }
    };

    action do_report_encapsulation(mac_t src_mac, mac_t mon_mac, ip_address_t src_ip,
                        ip_address_t mon_ip, l4_port_t mon_port) {
        //Report Ethernet Header
        hdr.report_ethernet.setValid();
        hdr.report_ethernet.dst_addr = mon_mac;
        hdr.report_ethernet.src_addr = src_mac;
        hdr.report_ethernet.ether_type = ETH_TYPE_IPV4;

        //Report IPV4 Header
        hdr.report_ipv4.setValid();
        hdr.report_ipv4.version = IP_VERSION_4;
        hdr.report_ipv4.ihl = IPV4_IHL_MIN;
        hdr.report_ipv4.dscp = DSCP_IP;
        hdr.report_ipv4.ecn = 2w0;

        // 20 + 8 + 16 + 14 + 20 + 8 + / 4 + 8 + (36 * #hops) / 84
        hdr.report_ipv4.len = (bit<16>) IPV4_MIN_HEAD_LEN + (bit<16>) UDP_HEADER_LEN + (bit<16>) REPORT_FIXED_HEADER_LEN +
                              (bit<16>) ETH_HEADER_LEN + (bit<16>) IPV4_MIN_HEAD_LEN + (bit<16>) UDP_HEADER_LEN + INT_DATA_LEN;

        hdr.report_ipv4.identification = 0;
        hdr.report_ipv4.flags = 0;
        hdr.report_ipv4.frag_offset = 0;
        hdr.report_ipv4.ttl = REPORT_HDR_TTL;
        hdr.report_ipv4.protocol = IP_PROTO_UDP;
        hdr.report_ipv4.src_addr = src_ip;
        hdr.report_ipv4.dst_addr = mon_ip;

        //Report UDP Header
        hdr.report_udp.setValid();
        hdr.report_udp.src_port = 1234;
        hdr.report_udp.dst_port = mon_port;
        hdr.report_udp.length_ = (bit<16>) UDP_HEADER_LEN + (bit<16>) REPORT_FIXED_HEADER_LEN +
                                 (bit<16>) ETH_HEADER_LEN + (bit<16>) IPV4_MIN_HEAD_LEN + (bit<16>) UDP_HEADER_LEN +
                                 INT_DATA_LEN;
        
        hdr.report_fixed_header.setValid();
        hdr.report_fixed_header.ver = 1;
        hdr.report_fixed_header.len = 4;
        hdr.report_fixed_header.nproto = NPROTO_ETHERNET;
        hdr.report_fixed_header.rep_md_bits = 0;
        hdr.report_fixed_header.d_q_f = 1;
        // hdr.report_fixed_header.q = 0;
        // hdr.report_fixed_header.f = 1;
        hdr.report_fixed_header.rsvd = 0;
        // get information specific to the switch
        hdr.report_fixed_header.hw_id = HW_ID;
        hdr.report_fixed_header.sw_id = local_metadata.int_meta.switch_id;

        // save a variable and increment
        hdr.report_fixed_header.seq_no = counter_incr.execute(0);

        hdr.report_fixed_header.ingress_tstamp =  (bit<32>) eg_prsr_md.global_tstamp;

    }

    table tb_generate_report {
        // key = {
        // }
        actions = {
            do_report_encapsulation;
            NoAction();
        }
        default_action = NoAction();
    }

    apply {
        tb_generate_report.apply();
    }
}


/*************************************************************************
****************  I N G R E S S   P R O C E S S I N G   ******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout local_metadata_t local_metadata,
                  in ingress_intrinsic_metadata_t ig_intr_md,
                  in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                  inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                  inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    

    apply {

        port_forward.apply(hdr, local_metadata, ig_tm_md, ig_dprsr_md);
        
        process_int_source_sink.apply(hdr, local_metadata, ig_intr_md, ig_tm_md);

        if (local_metadata.int_meta.source == _TRUE) {
            process_int_source.apply(hdr, local_metadata);
        }

        if (local_metadata.int_meta.sink == _TRUE && hdr.int_header.isValid()) {
            // clone packet for Telemetry Report
            ig_dprsr_md.mirror_type = MIRROR_TYPE_I2E;
            local_metadata.pkt_type = PKT_TYPE_MIRROR; 
            local_metadata.ing_mir_ses = (bit<10>) MIRROR_TYPE_I2E;

            // set a flag here
            hdr.local_report_header.do_report = _TRUE;
        }

        // Save ingress parser values for egress / INT Transit
        hdr.local_report_header.setValid();
        hdr.local_report_header.ingress_port_id = (bit<16>) ig_intr_md.ingress_port;
        hdr.local_report_header.queue_id = (bit<32>) ig_tm_md.qid;
        hdr.local_report_header.ingress_global_tstamp = ig_intr_md.ingress_mac_tstamp;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyIngressDeparser(packet_out packet, 
                            inout headers hdr, 
                            in local_metadata_t local_metadata, 
                            in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {   
    
    
    Mirror() mirror;
    
    apply {

        if(ig_dprsr_md.mirror_type == 3w1) {
            mirror.emit<mirror_h>(local_metadata.ing_mir_ses, {local_metadata.pkt_type, hdr.local_report_header.ingress_port_id, hdr.local_report_header.queue_id,hdr.local_report_header.ingress_global_tstamp});
        }
        
        packet.emit(hdr.local_report_header);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);

        packet.emit(hdr.intl4_shim);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_switch_id);
        packet.emit(hdr.int_level1_port_ids);
        packet.emit(hdr.int_hop_latency);
        packet.emit(hdr.int_q_occupancy);
        packet.emit(hdr.int_ingress_tstamp);
        packet.emit(hdr.int_egress_tstamp);
        packet.emit(hdr.int_level2_port_ids);
        packet.emit(hdr.int_egress_tx_util);

        packet.emit(hdr.int_data);
        
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

parser MyEgressParser(packet_in packet,
                        out headers hdr,
                        out local_metadata_t local_metadata,
                        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        packet.extract(eg_intr_md);
        transition parse_metadata;
    }

    state parse_metadata {
        mirror_h mirror_md = packet.lookahead<mirror_h>();
        transition select(mirror_md.pkt_type) {
            PKT_TYPE_MIRROR : parse_mirror_md;
            default : parse_ethernet;
        }
    }

    state parse_mirror_md {
        mirror_h mirror_md;
        packet.extract(hdr.mirror_header);
        local_metadata.sink = _TRUE;
        transition parse_ethernet_mirror;
    }

    state parse_ethernet {
        packet.extract(hdr.local_report_header);
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ethernet_mirror {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;
        transition select(hdr.ipv4.dscp) {
            DSCP_INT &&& DSCP_MASK: parse_shim;
            default:  accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition select(hdr.ipv4.dscp) {
            DSCP_INT &&& DSCP_MASK: parse_shim;
            default:  accept;
        }
    }

    state parse_shim {
        packet.extract(hdr.intl4_shim);
        transition parse_int_hdr;
    }

    state parse_int_hdr {
        packet.extract(hdr.int_header);
        transition parse_int_data;
    }

    state parse_int_data {
        
        // packet.extract(hdr.int_data); // if INT node is a source or transit node, no need to extract int data here. only for sink node. 
        packet.extract(hdr.int_data);
        transition select(hdr.mirror_header.pkt_type) {
            PKT_TYPE_MIRROR : parse_advance;
            default : accept;
        }
    }

    // if mirrored packet, skip over the rest of the payload as we are only interested in the int metadata
    state parse_advance {
        packet.advance(PACKET_ADVANCE);
        transition accept;
    }
}


control MyEgress(inout headers hdr,
                 inout local_metadata_t local_metadata,
                 in egress_intrinsic_metadata_t eg_intr_md,
                 in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
                 inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
                 inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    
    apply {
        if(hdr.int_header.isValid()) {

            process_set_sink.apply(hdr, local_metadata, eg_intr_md);

            if (local_metadata.int_meta.sink == _TRUE) {
                process_int_sink.apply(hdr, local_metadata);
                
            } else if (local_metadata.int_meta.sink == _FALSE) {
                if(hdr.mirror_header.isValid()) {
                    hdr.local_report_header.ingress_port_id = hdr.mirror_header.ingress_port_id;
                    hdr.local_report_header.queue_id = hdr.mirror_header.queue_id;
                    hdr.local_report_header.ingress_global_tstamp = hdr.mirror_header.ingress_global_tstamp;
                }
                process_int_transit.apply(hdr, local_metadata, eg_intr_md, eg_prsr_md);
            }
            
            if (local_metadata.sink == _TRUE) {       // Packet is a mirror
                process_int_report.apply(hdr, local_metadata, eg_intr_md, eg_prsr_md);
            }
        }

        hdr.local_report_header.setInvalid();
        hdr.mirror_header.setInvalid();
    }
}

/*************************************************************************
*********************** D E P A R S E R  *******************************
*************************************************************************/

control MyEgressDeparser(packet_out packet, 
                         inout headers hdr,
                         in local_metadata_t local_metadata, 
                         in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    
    Checksum() ipv4Checksum;
    
    apply {

        hdr.ipv4.hdr_checksum = ipv4Checksum.update(
             {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
             }
         );

        packet.emit(hdr.report_ethernet);
        packet.emit(hdr.report_ipv4);
        packet.emit(hdr.report_udp);
        packet.emit(hdr.report_fixed_header);

        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);

        packet.emit(hdr.intl4_shim);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_switch_id);
        packet.emit(hdr.int_level1_port_ids);
        packet.emit(hdr.int_hop_latency);
        packet.emit(hdr.int_q_occupancy);
        packet.emit(hdr.int_ingress_tstamp);
        packet.emit(hdr.int_egress_tstamp);
        packet.emit(hdr.int_level2_port_ids);
        packet.emit(hdr.int_egress_tx_util);

        packet.emit(hdr.int_data);
        
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

Pipeline(
        MyIngressParser(),
        MyIngress(),
        MyIngressDeparser(),
        MyEgressParser(),
        MyEgress(),
        MyEgressDeparser()
    ) pipe;

Switch(pipe) main;