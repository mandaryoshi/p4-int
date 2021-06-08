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

    action int_source(bit<4> ins_mask0003, bit<4> ins_mask0407) {
        
        hdr.intl4_shim.setValid();                              // insert INT shim header
        hdr.intl4_shim.int_type = 3;                            // int_type: Hop-by-hop type (1) , destination type (2), MX-type (3)
        hdr.intl4_shim.npt = 0;                                 // next protocol type: 0
        hdr.intl4_shim.len = INT_HEADER_LEN_WORD;               // This is 3 from 0xC (INT_TOTAL_HEADER_SIZE >> 2)
        hdr.intl4_shim.udp_ip_dscp = hdr.ipv4.dscp;             // although should be first 6 bits of the second byte
        hdr.intl4_shim.udp_ip = 0;                              // although should be first 6 bits of the second byte

        // insert INT header
        hdr.int_header.setValid();
        hdr.int_header.ver = 2;
        hdr.int_header.d = 0;
        hdr.int_header.instruction_mask_0003 = ins_mask0003;
        hdr.int_header.instruction_mask_0407 = ins_mask0407;
        hdr.int_header.instruction_mask_0811 = 0;               // bit 8 is buffer related, rest are reserved
        hdr.int_header.instruction_mask_1215 = 0;               // rsvd

        hdr.int_header.domain_specific_id = 0;                  // Unique INT Domain ID
        hdr.int_header.ds_instruction = 0;                      // Instruction bitmap specific to the INT Domain identified by the Domain specific ID
        hdr.int_header.ds_flags = 0;                            // Domain specific flags

        // add the header len (3 words) to total len
        hdr.ipv4.len = hdr.ipv4.len + INT_TOTAL_HEADER_SIZE;
        hdr.udp.length_ = hdr.udp.length_ + INT_TOTAL_HEADER_SIZE;

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
            int_source;
            NoAction;
        }
        const default_action = NoAction();
    }

    apply {
        tb_int_source.apply();
    }
}
