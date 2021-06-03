# In-Band Network Telemetry Implementation in P4

**INT-XD - eXport Data**

## Build

The P4 code can be compiled by using the build script in the SDE
```
./p4_build.sh int_xd.p4
```

The following topology can be referred to for the INT-XD mode of operation:
![INT-XD](../figures/int-xd.png)

## Usage

Run the P4 code as follows
```
$SDE/run_switchd.sh -p int_xd
```

### Populating the tables and registers

In another window for each switch, the following command can be run depending on the role of the INT node
```
$SDE/run_bfshell.sh -b $P4-INT/int-xd/bfrt_python/bfswitch1.py
```

### Testing the INT program

Packets can be sent from server1, and tcpdump/wireshark can be used to see the output at the monitoring server and the receiver 

