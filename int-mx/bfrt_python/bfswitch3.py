p4 = bfrt.int_mx.pipe

p4.MyIngress.port_forward.tb_port_forward.add_with_set_egress_port(dst_addr="10.0.0.0", dst_addr_p_length=24, port=396)
p4.MyEgress.process_set_sink.tb_set_sink.add_with_int_set_sink(egress_port=396)
p4.MyEgress.process_int_transit.tb_int_insert.set_default_with_init_metadata(switch_id=3)
p4.MyEgress.process_int_report.tb_generate_report.set_default_with_do_report_encapsulation(mon_ip="10.0.3.3", mon_mac="3c:fd:fe:ed:1d:c1", mon_port="4321", src_ip="172.26.0.4", src_mac="02:42:ac:1c:00:67")

bfrt.mirror.cfg.add_with_normal(sid=1, session_enable=True, direction='BOTH', ucast_egress_port=397, ucast_egress_port_valid=True, max_pkt_len=16000)