# In-Band Network Telemetry Implementation in P4

**A Prototype Implementation of INT Modes of Operation**

This project implements the three INT modes of operations as specified in the specifications of [INT v2.1](https://github.com/p4lang/p4-applications/blob/master/docs/INT_v2_1.pdf). INT v2.1 is used, and INT-MD is implemented for INT v1.0 as well.

The code was tested on `Stordis BF6064X-T` Tofino switches, running SDE version `9.4.0` using `Ubuntu 18.04.5 LTS`. The program used to generate traffic was `TRex`.

## Build

The P4 code can be compiled by using the build script in the SDE, for instance
```
./p4_build.sh int_mx.p4
```

Additional information is provided in the folders for each mode of operation: [INT-MD 1.0](int-md-1-0/README.md), [INT-MD 2.1](int-md-2-1/README.md), [INT-MX](int-mx/README.md) and [INT-XD](int-xd/README.md). Each folder also contains the topology used. 

## Usage

Run the P4 code as follows, for example:
```
$SDE/run_switchd.sh -p int_mx
```

## Limitations

The following features have not been implemented:
- Domain namespaces
- Drop reports

## Authors

- Mandar Joshi, Saab/KTH

## License

This project is distributed using GNU GPLv2, see [LICENSE](LICENSE).
