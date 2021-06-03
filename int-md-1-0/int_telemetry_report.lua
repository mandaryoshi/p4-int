-- Auto-generated dissector from P4 header

-- Helper functions

-- Return a slice of a table
function table_slice(input_table, first, last)
    local subtable = {}
    for i = first, last do
      subtable[#subtable + 1] = input_table[i]
    end
    return subtable
  end
  
  -- Convert a number to bits
  function tobits(number, bitcount, first_bit, last_bit)
      local bit_table = {}
      for bit_index = bitcount, 1, -1 do
          remainder = math.fmod(number, 2)
          bit_table[bit_index] = remainder
          number = (number - remainder) / 2
      end
      return table.concat(table_slice(bit_table, first_bit, last_bit))
  end
  
  
  -- Auto generated section
  
  p4_proto = Proto("p4_report_fixed_header","P4_REPORT_FIXED_HEADER Protocol")
  p4_int_proto = Proto("p4_int_header", "P4_INT_HEADER Protocol")
  
  function p4_proto.dissector(buffer,pinfo,tree)
      pinfo.cols.protocol = "P4_REPORT_FIXED_HEADER"
      local subtree_report = tree:add(p4_proto,buffer(),"Telemetry Report Fixed Header")
      subtree_report:add(buffer(0,1), "ver (4 bits) - Binary: " .. tobits(buffer(0,1):uint(), 8, 1, 4))
      subtree_report:add(buffer(0,1), "len (4 bits) - Binary: " .. tobits(buffer(0,1):uint(), 8, 5, 8))
      subtree_report:add(buffer(1,3), "nproto (3 bits) - Binary: " .. tobits(buffer(1,3):uint(), 24, 1, 3))
      subtree_report:add(buffer(1,3), "rep_md_bits (6 bits) - Binary: " .. tobits(buffer(1,3):uint(), 24, 4, 9))
      subtree_report:add(buffer(1,3), "d (1 bits) - Binary: " .. tobits(buffer(1,3):uint(), 24, 10, 10))
      subtree_report:add(buffer(1,3), "q (1 bits) - Binary: " .. tobits(buffer(1,3):uint(), 24, 11, 11))
      subtree_report:add(buffer(1,3), "f (1 bits) - Binary: " .. tobits(buffer(1,3):uint(), 24, 12, 12))
      subtree_report:add(buffer(1,3), "rsvd (6 bits) - Binary: " .. tobits(buffer(1,3):uint(), 24, 13, 18))
      subtree_report:add(buffer(1,3), "hw_id (6 bits) - Binary: " .. tobits(buffer(1,3):uint(), 24, 19, 24))
      subtree_report:add(buffer(4,4), "sw_id (32 bits) - Hex: " .. string.format("%08X", buffer(4,4):bitfield(0, 32)))
      subtree_report:add(buffer(8,4), "seq_no (32 bits) - Hex: " .. string.format("%08X", buffer(8,4):bitfield(0, 32)))
      subtree_report:add(buffer(12,4), "ingress_tstamp (32 bits) - Hex: " .. string.format("%08X", buffer(12,4):bitfield(0, 32)))
      
      local subtree_eth = subtree_report:add(p4_int_proto,buffer(),"Ethernet II")
      -- Started Ethernet parsing
      subtree_eth:add(buffer(16,6), "dst_addr (48 bits) - Hex: " .. string.format("%02x:%02x:%02x:%02x:%02x:%02x", 
                                  buffer(16,1):bitfield(0, 8), buffer(17,1):bitfield(0, 8), 
                                  buffer(18,1):bitfield(0, 8), buffer(19,1):bitfield(0, 8), 
                                  buffer(20,1):bitfield(0, 8), buffer(21,1):bitfield(0, 8)))
      subtree_eth:add(buffer(22,6), "src_addr (48 bits) - Hex: " .. string.format("%02x:%02x:%02x:%02x:%02x:%02x", 
                                  buffer(22,1):bitfield(0, 8), buffer(23,1):bitfield(0, 8), 
                                  buffer(24,1):bitfield(0, 8), buffer(25,1):bitfield(0, 8), 
                                  buffer(26,1):bitfield(0, 8), buffer(27,1):bitfield(0, 8)))
      subtree_eth:add(buffer(28,2), "ethertype (16 bits) - Hex: " .. string.format("%04X", buffer(28,2):bitfield(0, 16)))
  
      local subtree_ipv4 = subtree_report:add(p4_int_proto,buffer(),"Internet Protocol Version 4")
      -- Started IPV4 parsing
      subtree_ipv4:add(buffer(30,1), "version (4 bits) - Binary: " .. tobits(buffer(30,1):uint(), 8, 1, 4))
      subtree_ipv4:add(buffer(30,1), "ihl (4 bits) - Binary: " .. tobits(buffer(30,1):uint(), 8, 5, 8))
      subtree_ipv4:add(buffer(31,1), "dscp (6 bits) - Binary: " .. tobits(buffer(31,1):uint(), 8, 1, 6))
      subtree_ipv4:add(buffer(31,1), "ecn (2 bits) - Binary: " .. tobits(buffer(31,1):uint(), 8, 7, 8))
      subtree_ipv4:add(buffer(32,2), "len (16 bits) - Hex: " .. string.format("%04X", buffer(32,2):bitfield(0, 16)))
      subtree_ipv4:add(buffer(34,2), "identification (16 bits) - Hex: " .. string.format("%04X", buffer(34,2):bitfield(0, 16)))
      subtree_ipv4:add(buffer(36,1), "flags (3 bits) - Binary: " .. tobits(buffer(36,1):uint(), 8, 1, 3))
      subtree_ipv4:add(buffer(36,2), "frag_offset (13 bits) - Hex: " .. string.format("%04X", buffer(36,2):bitfield(3, 13)))
      subtree_ipv4:add(buffer(38,1), "ttl (8 bits) - Hex: " .. string.format("%02X", buffer(38,1):bitfield(0, 8)))
      subtree_ipv4:add(buffer(39,1), "protocol (8 bits) - Hex: " .. string.format("%02X", buffer(39,1):bitfield(0, 8)))
      ipv4_protocol = buffer(39,1):bitfield(0,8)
      subtree_ipv4:add(buffer(40,2), "hdr_checksum (16 bits) - Hex: " .. string.format("%04X", buffer(40,2):bitfield(0, 16)))
      -- subtree_ipv4:add(buffer(38,4), "src_addr (32 bits) - Hex: " .. string.format("%08X", buffer(38,4):bitfield(0, 32)))
      subtree_ipv4:add(buffer(42,4), "src_addr (32 bits) - " .. string.format("%d.%d.%d.%d", 
                                  buffer(42,1):bitfield(0, 8), buffer(43,1):bitfield(0, 8), 
                                  buffer(44,1):bitfield(0, 8), buffer(45,1):bitfield(0, 8)))
      -- subtree_ipv4:add(buffer(42,4), "dst_addr (32 bits) - " .. string.format("%08X", buffer(42,4):bitfield(0, 32)))
      subtree_ipv4:add(buffer(46,4), "dst_addr (32 bits) - " .. string.format("%d.%d.%d.%d", 
                                  buffer(46,1):bitfield(0, 8), buffer(47,1):bitfield(0, 8), 
                                  buffer(48,1):bitfield(0, 8), buffer(49,1):bitfield(0, 8)))
  
      local subtree_ipv4_proto
      -- TCP
      if(ipv4_protocol == 0x06) then
          subtree_ipv4_proto = subtree_report:add(p4_int_proto,buffer(),"Transmission Control Protocol")
      -- UDP 	
      else -- ipv4_protocol == 0x11
          subtree_ipv4_proto = subtree_report:add(p4_int_proto,buffer(),"User Datagram Protocol")
      end
  
      subtree_ipv4_proto:add(buffer(50,2), "src_port (16 bits) - " .. string.format("%d", buffer(50,2):bitfield(0, 16)))
      subtree_ipv4_proto:add(buffer(52,2), "dst_port (16 bits) - " .. string.format("%d", buffer(52,2):bitfield(0, 16)))
      subtree_ipv4_proto:add(buffer(54,2), "len (16 bits) - Hex: " .. string.format("%04X", buffer(54,2):bitfield(0, 16)))
      --subtree_ipv4_proto:add(buffer(50,4), "seq_no (32 bits) - Hex: " .. string.format("%08X", buffer(50,4):bitfield(0, 32)))
      --subtree_ipv4_proto:add(buffer(54,4), "ack_no (32 bits) - Hex: " .. string.format("%08X", buffer(54,4):bitfield(0, 32)))
      --subtree_ipv4_proto:add(buffer(58,1), "data_offset (4 bits) - Binary: " .. tobits(buffer(58,1):uint(), 8, 1, 4))
      --subtree_ipv4_proto:add(buffer(58,1), "res (3 bits) - Binary: " .. tobits(buffer(58,1):uint(), 8, 5, 7))
      --subtree_ipv4_proto:add(buffer(58,2), "ecn (3 bits) - Binary: " .. tobits(buffer(58,2):uint(), 16, 8, 10))
      --subtree_ipv4_proto:add(buffer(59,1), "ctrl (6 bits) - Binary: " .. tobits(buffer(59,1):uint(), 8, 3, 8))
      --subtree_ipv4_proto:add(buffer(60,2), "window (16 bits) - Hex: " .. string.format("%04X", buffer(60,2):bitfield(0, 16)))
      subtree_ipv4_proto:add(buffer(56,2), "checksum (16 bits) - Hex: " .. string.format("%04X", buffer(56,2):bitfield(0, 16)))
      --subtree_ipv4_proto:add(buffer(64,2), "urgent_ptr (16 bits) - Hex: " .. string.format("%04X", buffer(64,2):bitfield(0, 16)))
  
  
      local subtree_int = subtree_report:add(p4_int_proto,buffer(),"INT")
      local subtree_int_shim = subtree_int:add(p4_int_proto,buffer(),"INT Shim")
      
      --parse INT shim header -- intl4_shim
      subtree_int_shim:add(buffer(58,1), "int_type (8 bits) - Hex: " .. string.format("%02X", buffer(58,1):bitfield(0, 8)))
      subtree_int_shim:add(buffer(59,1), "rsvd1 (8 bits) - Hex: " .. string.format("%02X", buffer(59,1):bitfield(0, 8)))
      subtree_int_shim:add(buffer(60,1), "len (8 bits) - Hex: " .. string.format("%02X", buffer(60,1):bitfield(0, 8)))
      --subtree_int_shim:add(buffer(61,1), "dscp (6 bits) - Hex: " .. string.format("%02X", buffer(61,1):bitfield(0, 6)))
      --subtree_int_shim:add(buffer(61,1), "rsvd2 (2 bits) - Hex: " .. string.format("%02X", buffer(61,1):bitfield(6, 8)))
      subtree_int_shim:add(buffer(61,1), "dscp (6 bits) - Binary: " .. tobits(buffer(61,1):uint(), 8, 1, 6))
      subtree_int_shim:add(buffer(61,1), "rsvd (2 bits) - Binary: " .. tobits(buffer(61,1):uint(), 8, 7, 8))
  
      local subtree_int_header = subtree_int:add(p4_int_proto,buffer(),"INT Header")
      
      --parse INT metadata header -- int_header
      subtree_int_header:add(buffer(62,1), "ver (4 bits) - Binary: " .. tobits(buffer(62,1):uint(), 8, 1, 4))
      subtree_int_header:add(buffer(62,1), "rep (2 bits) - Binary: " .. tobits(buffer(62,1):uint(), 8, 5, 6))
      subtree_int_header:add(buffer(62,1), "c (1 bit) - Binary: " .. tobits(buffer(62,1):uint(), 8, 7, 7))
      subtree_int_header:add(buffer(62,1), "e (1 bit) - Binary: " .. tobits(buffer(62,1):uint(), 8, 8, 8))
      subtree_int_header:add(buffer(63,1), "m (1 bit) - Binary: " .. tobits(buffer(63,1):uint(), 8, 1, 1))
      subtree_int_header:add(buffer(63,1), "rsvd1 (7 bits) - Binary: " .. tobits(buffer(63,1):uint(), 8, 2, 8))
      subtree_int_header:add(buffer(64,1), "rsvd2 (3 bits) - Binary: " .. tobits(buffer(64,1):uint(), 8, 1, 3))
      subtree_int_header:add(buffer(64,1), "hop_metadata_len (5 bits) - Binary: " .. tobits(buffer(64,1):uint(), 8, 4, 8))
      subtree_int_header:add(buffer(65,1), "remaining_hop_cnt (8 bits) - " .. string.format("%d", buffer(65,1):bitfield(0, 8)))
      --subtree_int_header:add(buffer(73,1), "totalHopCnt (8 bits) - " .. string.format("%d", buffer(73,1):bitfield(0, 8)))
      totalHopCnt = buffer(65,1):bitfield(0, 8) -- Switch Number
      subtree_int_header:add(buffer(66,2), "instructionBitmap (16 bits) - Hex: " .. string.format("%04X", buffer(66,2):bitfield(0, 16)))
      instBitmap = buffer(66,2):bitfield(0, 16) -- Instruction Bitmap
      subtree_int_header:add(buffer(68,2), "rsvd3 (16 bits) - Hex: " .. string.format("%04X", buffer(68,2):bitfield(0, 16)))
     
      local subtree_int_data = subtree_int:add(p4_int_proto,buffer(),"INT Data")
      
      --parse INT metadata -- int_data
      curser = 70
      index = 0
      subtree_str = ""
      for i = 1, 3 do
          subtree_str = string.format("%s%d", "switch_", index)
          index = index + 1
          
          local subtree_switch = subtree_int_data:add(p4_int_proto,buffer(),subtree_str)
  
          if(bit.band(instBitmap, 0x8000) ~= 0) then
              subtree_switch:add(buffer(curser,4), "switch_id (32 bits) - Hex: " .. string.format("%08X", buffer(curser,4):bitfield(0, 32)))
              curser = curser + 4
          end
          if(bit.band(instBitmap, 0x4000) ~= 0) then
              subtree_switch:add(buffer(curser, 2), "ingress_port_id (16 bits) - " .. string.format("%d", buffer(curser,2):bitfield(0, 16)))
              subtree_switch:add(buffer(curser+2, 2), "engress_port_id (16 bits) - " .. string.format("%d", buffer(curser+2,2):bitfield(0, 16)))
              curser = curser + 4
          end
          if(bit.band(instBitmap, 0x2000) ~= 0) then
              subtree_switch:add(buffer(curser, 4), "hop_latency (32 bits) - Hex: " .. string.format("%08X", buffer(curser,4):bitfield(0, 32)))
              curser = curser + 4
          end
          if(bit.band(instBitmap, 0x1000) ~= 0) then
              subtree_switch:add(buffer(curser,1), "q_id (8 bits) - " .. string.format("%d", buffer(curser,1):bitfield(0, 8)))
              subtree_switch:add(buffer(curser+1,3), "q_occupancy (24 bits) - Hex: " .. string.format("%08X", buffer(curser+1,3):bitfield(0, 24)))
              curser = curser + 4
          end
          if(bit.band(instBitmap, 0x0800) ~= 0) then
              subtree_switch:add(buffer(curser, 4), "ingress_tstamp (32 bits) - Hex: " .. string.format("%08X", buffer(curser,4):bitfield(0, 32)))
              curser = curser + 4
          end
          if(bit.band(instBitmap, 0x0400) ~= 0) then
              subtree_switch:add(buffer(curser,4), "egress_tstamp (32 bits) - Hex: " .. string.format("%08X", buffer(curser,4):bitfield(0, 32)))
              curser = curser + 4
          end
          if(bit.band(instBitmap, 0x0200) ~= 0) then
              --subtree_switch:add(buffer(curser,1), "q_id (8 bits) - " .. string.format("%d", buffer(curser,1):bitfield(0, 8)))
              --subtree_switch:add(buffer(curser,3), "q_congestion (24 bits) - Hex: " .. string.format("%06X", buffer(curser, 3):bitfield(0, 24)))
              subtree_switch:add(buffer(curser, 4), "ingress_port_id (32 bits) - Hex: " .. string.format("%08X", buffer(curser,4):bitfield(0, 32)))
              subtree_switch:add(buffer(curser+4, 4), "egress_port_id (32 bits) - Hex: " .. string.format("%08X", buffer(curser+4,4):bitfield(0, 32)))
              curser = curser + 8
          end
          if(bit.band(instBitmap, 0x0100) ~= 0) then
              subtree_switch:add(buffer(curser,4), "egress_port_tx_util (32 bits) - Hex: " .. string.format("%08X", buffer(curser,4):bitfield(0, 32)))
              curser = curser + 4
          end
      end
  
      -- local subtree_int_tail = subtree_int:add(p4_int_proto,buffer(),"INT Tail")
      
      -- --parse intl4_tail
      -- subtree_int_tail:add(buffer(curser,1), "next_proto (8 bits) - Hex: " .. string.format("%02X", buffer(curser,1):bitfield(0, 8)))
      -- curser = curser + 1
      -- subtree_int_tail:add(buffer(curser,2), "dest_port (16 bits) - " .. string.format("%d", buffer(curser,2):bitfield(0, 16)))
      -- curser = curser + 2
      -- subtree_int_tail:add(buffer(curser,1), "dscp (8 bits) - Hex: " .. string.format("%02X", buffer(curser,1):bitfield(0, 8)))
  
  end
  
  my_table = DissectorTable.get("udp.port")
  my_table:add(1234, p4_proto)
  