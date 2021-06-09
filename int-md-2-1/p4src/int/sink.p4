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

control process_int_sink (
    inout headers hdr,
    inout local_metadata_t local_metadata) {
    
    action restore_header () {
        hdr.ipv4.dscp = hdr.intl4_shim.udp_ip_dscp;
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
        hdr.report_ipv4.dscp = 6w0;
        hdr.report_ipv4.ecn = 2w0;

        // 20 + 8 + 16 + 14 + 20 + 8 + / 4 + 8 + (36 * #hops) / 84
        hdr.report_ipv4.len = (bit<16>) IPV4_MIN_HEAD_LEN + (bit<16>) UDP_HEADER_LEN + (bit<16>) REPORT_GROUP_HEADER_LEN +
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
        hdr.report_udp.length_ = (bit<16>) UDP_HEADER_LEN + (bit<16>) REPORT_GROUP_HEADER_LEN +
                                 (bit<16>) ETH_HEADER_LEN + (bit<16>) IPV4_MIN_HEAD_LEN + (bit<16>) UDP_HEADER_LEN +
                                 INT_DATA_LEN;
        
        hdr.report_group_header.setValid();
        hdr.report_group_header.ver = 2;
        hdr.report_group_header.hw_id = HW_ID;
        hdr.report_group_header.seq_no = 0;
        // TODO:
        // (bit<22>) counter_incr.execute(0);
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