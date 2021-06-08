//Action to set node as INT sink in the egress for mirrored packets, however, this could be made as a flag based on the previous action instead
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

// Actions run in the egress of the INT Sink, before packet is forwarded to end-host
control process_int_sink (
    inout headers hdr,
    inout local_metadata_t local_metadata) {
    
    action restore_header () {
        // restore length fields of IPv4 header and UDP header, and IP DSCP which was stored in the INT SHIM Header
        hdr.ipv4.dscp = hdr.mirror_header.udp_ip_dscp;
        hdr.ipv4.len = hdr.ipv4.len - INT_TOTAL_HEADER_SIZE;
        hdr.udp.length_ = hdr.udp.length_ - INT_TOTAL_HEADER_SIZE;
        
    }
    
    action int_sink() {
        // remove all the INT information from the packet
        hdr.int_header.setInvalid();
        hdr.intl4_shim.setInvalid();
        hdr.mirror_header.setInvalid();
    }

    apply {
        restore_header();
        int_sink();
    }
}

// This is an action to insert INT header from the mirror header into the new packet
control process_int_header (
    inout headers hdr,
    inout local_metadata_t local_metadata) {
    
    action add_int_header() {

        hdr.intl4_shim.setValid();                              
        hdr.intl4_shim.int_type = hdr.mirror_header.int_type;
        hdr.intl4_shim.npt = hdr.mirror_header.npt;
        hdr.intl4_shim.len = hdr.mirror_header.len;
        hdr.intl4_shim.udp_ip_dscp = hdr.mirror_header.udp_ip_dscp;
        hdr.intl4_shim.udp_ip = hdr.mirror_header.udp_ip;

        
        hdr.int_header.setValid();
        hdr.int_header.ver = hdr.mirror_header.ver;
        hdr.int_header.d = hdr.mirror_header.d;
        hdr.int_header.instruction_mask_0003 = hdr.mirror_header.instruction_mask_0003;
        hdr.int_header.instruction_mask_0407 = hdr.mirror_header.instruction_mask_0407;
        hdr.int_header.instruction_mask_0811 = hdr.mirror_header.instruction_mask_0811;
        hdr.int_header.instruction_mask_1215 = hdr.mirror_header.instruction_mask_1215;
    }

    apply {
        add_int_header();
    }
}


// Action for the INT telemetry report, as it is encapsulated with new Ethernet, IP and UDP headers
control process_int_report (
    inout headers hdr,
    inout local_metadata_t local_metadata,
    in egress_intrinsic_metadata_t eg_intr_md) {

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
        hdr.report_ipv4.dscp = 6w0;
        hdr.report_ipv4.ecn = 2w0;
        /* Total Len is  */
        // 8 + 8 + 8 + 8 + 8 + 8
        hdr.report_ipv4.len = (bit<16>) IPV4_MIN_HEAD_LEN + (bit<16>) UDP_HEADER_LEN + (bit<16>) REPORT_GROUP_HEADER_LEN + (bit<16>) REPORT_INDIVIDUAL_HEADER_LEN +
                              (bit<16>) ETH_HEADER_LEN + (bit<16>) IPV4_MIN_HEAD_LEN + (bit<16>) UDP_HEADER_LEN + SHIM_LEN;

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
        hdr.report_udp.length_ = (bit<16>) UDP_HEADER_LEN + (bit<16>) REPORT_GROUP_HEADER_LEN + (bit<16>) REPORT_INDIVIDUAL_HEADER_LEN + 
                                 (bit<16>) ETH_HEADER_LEN + (bit<16>) IPV4_MIN_HEAD_LEN + (bit<16>) UDP_HEADER_LEN + SHIM_LEN;

        /* Telemetry Group Header */

        hdr.report_group_header.setValid();
        hdr.report_group_header.ver = 1;
        hdr.report_group_header.hw_id = HW_ID;
        hdr.report_group_header.seq_no = 0;
        hdr.report_group_header.node_id = local_metadata.int_meta.switch_id;

        /* Telemetry Report Individual Header */
        hdr.report_individual_header.setValid();
        hdr.report_individual_header.rep_type = 1;
        hdr.report_individual_header.in_type = 4;
        hdr.report_individual_header.len = 0;
        hdr.report_individual_header.rep_md_len = 0;
        hdr.report_individual_header.d = 0;
        hdr.report_individual_header.q = 0;
        hdr.report_individual_header.f = 1;
        hdr.report_individual_header.i = 1;
        hdr.report_individual_header.rsvd = 0;

        /* Individual report inner contents */

        hdr.report_individual_header.rep_md_bits = 0;
        hdr.report_individual_header.domain_specific_id = 0;
        hdr.report_individual_header.domain_specific_md_bits = 0;
        hdr.report_individual_header.domain_specific_md_status = 0;
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