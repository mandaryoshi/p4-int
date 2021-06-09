// This action sets the node as a INT source or INT sink in the ingress pipeline
// INT Source is set by the ingress port and INT Sink is set by the egress port
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