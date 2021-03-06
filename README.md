# ICSNPP-S7COMM

Industrial Control Systems Network Protocol Parsers (ICSNPP) - s7comm, s7comm-plus, and COTP.

## Overview

ICSNPP-S7COMM is a Zeek plugin for parsing and logging fields within the s7comm, s7comm-plus, and COTP protocols.

This plugin was developed to be fully customizable, so if you would like to drill down into specific packets and log certain variables, add the logging functionality to [scripts/icsnpp/s7comm/main.zeek](scripts/icsnpp/s7comm/main.zeek). The functions within [scripts/icsnpp/s7comm/main.zeek](scripts/icsnpp/s7comm/main.zeek) and [src/events.bif](src/events.bif) should prove to be a good guide on how to add new logging functionality.

This parser currently produces three log files. These log files are defined in [scripts/icsnpp/s7comm/main.zeek](scripts/icsnpp/s7comm/main.zeek).
* cotp.log
* s7comm.log
* s7comm_plus.log

For additional information on these log files, see the *Logging Capabilities* section below.

## Installation

### Package Manager

This script is available as a package for [Zeek Package Manger](https://docs.zeek.org/projects/package-manager/en/stable/index.html)

```bash
zkg refresh
zkg install icsnpp-s7comm
```

If this package is installed from ZKG it will be added to the available plugins. This can be tested by running `zeek -N`. If installed correctly you will see `ICSNPP::S7COMM`.

If you have ZKG configured to load packages (see @load packages in quickstart guide), this plugin and scripts will automatically be loaded and ready to go.
[ZKG Quickstart Guide](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html)

If you are not using site/local.zeek or another site installation of Zeek and just want to run this package on a packet capture you can add `icsnpp/s7comm` to your command to run this plugin's scripts on the packet capture:

```bash
git clone https://github.com/cisagov/icsnpp-s7comm.git
zeek -Cr icsnpp-s7comm/examples/s7comm_plus_example.pcap icsnpp/s7comm
```

### Manual Install

To install this package manually, clone this repository and run the configure and make commands as shown below.

```bash
git clone https://github.com/cisagov/icsnpp-s7comm.git
cd icsnpp-s7comm/
./configure
make
```

If these commands succeed, you will end up with a newly create build directory. This contains all the files needed to run/test this plugin. The easiest way to test the parser is to point the ZEEK_PLUGIN_PATH environment variable to this build directory.

```bash
export ZEEK_PLUGIN_PATH=$PWD/build/
zeek -N # Ensure everything compiled correctly and you are able to see ICSNPP::S7COMM
```

Once you have tested the functionality locally and it appears to have compiled correctly, you can install it system-wide:
```bash
sudo make install
unset ZEEK_PLUGIN_PATH
zeek -N # Ensure everything installed correctly and you are able to see ICSNPP::S7COMM
```

To run this plugin in a site deployment you will need to add the line `@load icsnpp/s7comm` to your `site/local.zeek` file in order to load this plugin's scripts.

If you are not using site/local.zeek or another site installation of Zeek and just want to run this package on a packet capture you can add `icsnpp/s7comm` to your command to run this plugin's scripts on the packet capture:

```bash
zeek -Cr icsnpp-s7comm/examples/s7comm_plus_example.pcap icsnpp/s7comm
```

If you want to deploy this on an already existing Zeek implementation and you don't want to build the plugin on the machine, you can extract the ICSNPP_S7comm.tgz file to the directory of the established ZEEK_PLUGIN_PATH (default is `${ZEEK_INSTALLATION_DIR}/lib/zeek/plugins/`).

```bash
tar xvzf build/ICSNPP_S7comm.tgz -C $ZEEK_PLUGIN_PATH 
```

## Logging Capabilities

### COTP Log (cotp.log)

#### Overview

This log captures COTP information for every COTP packet and logs it to **cotp.log**.

#### Fields Captured

| Field             | Type      | Description                                               |
| ----------------- |-----------|-----------------------------------------------------------| 
| ts                | time      | Timestamp                                                 |
| uid               | string    | Unique ID for this Connection                             |
| id                | conn_id   | Default Zeek Connection Info (IP addresses, ports)        |
| pdu_code          | string    | COTP PDU Type Code (in hex)                               |
| pdu_name          | string    | COTP PDU Name                                             |

### S7COMM Header Log (s7comm.log)

#### Overview

This log captures s7comm header information for every s7comm packet and logs it to **s7comm.log**.

#### Fields Captured

| Field                 | Type      | Description                                               |
| --------------------- |-----------|-----------------------------------------------------------|
| ts                    | time      | Timestamp                                                 |
| uid                   | string    | Unique ID for this Connection                             |
| id                    | conn_id   | Default Zeek Connection Info (IP addresses, ports)        |
| rosctr_code           | count     | Remote Operating Service Control Code (in hex)            |
| rosctr_name           | string    | Remote Operating Service Control Name                     |
| pdu_reference         | count     | Reference ID Used to Link Requests to Responses           |
| function_code         | string    | Parameter Function Code (in hex)                          |
| function_name         | string    | Parameter Function Name                                   |
| error_class           | string    | Error Class Name                                          |
| error_code            | string    | Error Code within Error Class                             |

### S7COMM-PLUS Log (s7comm_plus.log)

#### Overview

This log captures s7comm-plus header information for every s7comm packet and logs it to **s7comm_plus.log**.

#### Fields Captured

| Field                 | Type      | Description                                               |
| --------------------- |-----------|-----------------------------------------------------------|
| ts                    | time      | Timestamp                                                 |
| uid                   | string    | Unique ID for this Connection                             |
| id                    | conn_id   | Default Zeek Connection Info (IP addresses, ports)        |
| version               | count     | S7comm-plus Version                                       |
| opcode                | string    | Opcode Code (in hex)                                      |
| opcode_name           | string    | Opcode Name                                               |
| function_code         | string    | Opcode Function Code (in hex)                             |
| function_name         | string    | Opcode Function Name                                      |

## ICSNPP Packages

All ICSNPP Packages:
* [ICSNPP](https://github.com/cisagov/icsnpp)

Full ICS Protocol Parsers:
* [BACnet](https://github.com/cisagov/icsnpp-bacnet)
    * Full Zeek protocol parser for BACnet (Building Control and Automation)
* [BSAP](https://github.com/cisagov/icsnpp-bsap)
    * Full Zeek protocol parser for BSAP (Bristol Standard Asynchronous Protocol) over IP
    * Full Zeek protocol parser for BSAP Serial comm converted using serial tap device
* [Ethercat](https://github.com/cisagov/icsnpp-ethercat)
    * Full Zeek protocol parser for Ethercat
* [Ethernet/IP and CIP](https://github.com/cisagov/icsnpp-enip)
    * Full Zeek protocol parser for Ethernet/IP and CIP
* [Genisys](https://github.com/cisagov/icsnpp-genisys)
    * Full Zeek protocol parser for Genisys
* [OPCUA-Binary](https://github.com/cisagov/icsnpp-opcua-binary)
    * Full Zeek protocol parser for OPC UA (OPC Unified Architecture) - Binary
* [S7Comm](https://github.com/cisagov/icsnpp-s7comm)
    * Full Zeek protocol parser for S7comm, S7comm-plus, and COTP

Updates to Zeek ICS Protocol Parsers:
* [DNP3](https://github.com/cisagov/icsnpp-dnp3)
    * DNP3 Zeek script extending logging capabilities of Zeek's default DNP3 protocol parser
* [Modbus](https://github.com/cisagov/icsnpp-modbus)
    * Modbus Zeek script extending logging capabilities of Zeek's default Modbus protocol parser

### Other Software
Idaho National Laboratory is a cutting edge research facility which is a constantly producing high quality research and software. Feel free to take a look at our other software and scientific offerings at:

[Primary Technology Offerings Page](https://www.inl.gov/inl-initiatives/technology-deployment)

[Supported Open Source Software](https://github.com/idaholab)

[Raw Experiment Open Source Software](https://github.com/IdahoLabResearch)

[Unsupported Open Source Software](https://github.com/IdahoLabCuttingBoard)

### License

Copyright 2022 Battelle Energy Alliance, LLC

Licensed under the 3-Part BSD (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  https://opensource.org/licenses/BSD-3-Clause

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.




Licensing
-----
This software is licensed under the terms you may find in the file named "LICENSE" in this directory.