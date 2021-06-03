
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
        transition accept;
    }
}

/*************************************************************************
*********************** P A R S E R  *******************************
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
            mirror.emit<mirror_h>(local_metadata.ing_mir_ses, 
            {local_metadata.pkt_type, 
            hdr.local_report_header.ingress_port_id, 
            hdr.local_report_header.egress_port_id, 
            hdr.local_report_header.queue_id, 
            hdr.local_report_header.ingress_global_tstamp,
            hdr.intl4_shim.int_type,
            hdr.intl4_shim.npt,               
            hdr.intl4_shim.rsvd,                  
            hdr.intl4_shim.len,                     
            hdr.intl4_shim.udp_ip_dscp,          
            hdr.intl4_shim.udp_ip,            
            hdr.int_header.ver,                    
            hdr.int_header.d,                      
            hdr.int_header.rsvd,                                  
            hdr.int_header.instruction_mask_0003, 
            hdr.int_header.instruction_mask_0407,
            hdr.int_header.instruction_mask_0811,
            hdr.int_header.instruction_mask_1215,
            hdr.int_header.domain_specific_id,     
            hdr.int_header.ds_instruction,         
            hdr.int_header.ds_flags     
            });
        }
        
        //packet.emit(hdr);
        packet.emit(hdr.local_report_header);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);

        packet.emit(hdr.intl4_shim);
        packet.emit(hdr.int_header);
    }
}

/*************************************************************************
*********************** D E P A R S E R  *******************************
*************************************************************************/

control MyEgressDeparser(packet_out packet, 
                         inout headers hdr,
                         in local_metadata_t local_metadata, 
                         in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    
    // Mirror() mirror;

    Checksum() ipv4Checksum;
    
    apply {

        // Egress mirroring if ncessary
        

        // if(eg_dprsr_md.mirror_type == MIRROR_TYPE_E2E) {
        //     mirror.emit<mirror_h>(local_metadata.egr_mir_ses, {local_metadata.pkt_type, hdr.local_report_header.ingress_port_id, 
        //     hdr.local_report_header.queue_id, hdr.local_report_header.ingress_global_tstamp});
        // }

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

        // //parsed headers have to be added again into the packet.
        //packet.emit(hdr);
        packet.emit(hdr.report_ethernet);
        packet.emit(hdr.report_ipv4);
        packet.emit(hdr.report_udp);
        packet.emit(hdr.report_group_header);
        packet.emit(hdr.report_individual_header);

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
        
    }
}