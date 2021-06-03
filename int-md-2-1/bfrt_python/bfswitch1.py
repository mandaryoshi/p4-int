p4 = bfrt.int_md_1_0.pipe

p4.MyIngress.port_forward.tb_port_forward.add_with_set_egress_port(dst_addr="10.0.2.2", dst_addr_p_length=32, port=7)
p4.MyIngress.process_int_source_sink.tb_set_source.add_with_int_set_source(ingress_port=5)
p4.MyIngress.process_int_source.tb_int_source.add_with_int_source_dscp(dst_addr="10.0.2.2", dst_addr_p_length=32, hop_metadata_len=16, remaining_hop_cnt=3, ins_mask0003=15, ins_mask0407=15)
p4.MyEgress.process_int_transit.tb_int_insert.set_default_with_init_metadata(switch_id=1)