p4 = bfrt.int_md_1_0.pipe

p4.MyIngress.port_forward.tb_port_forward.add_with_set_egress_port(dst_addr="10.0.2.2", dst_addr_p_length=32, port=11)
p4.MyEgress.process_int_transit.tb_int_insert.set_default_with_init_metadata(switch_id=2)