// Simple action to forward the packet based on the ipv4 destination address
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
