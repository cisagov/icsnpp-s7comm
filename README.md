# ICSNPP-S7COMM

Industrial Control Systems Network Protocol Parsers (ICSNPP) - s7comm, s7comm-plus, and COTP.

## Overview

ICSNPP-S7COMM is a Zeek plugin for parsing and logging fields within the s7comm, s7comm-plus, and COTP protocols.

This plugin was developed to be fully customizable, so if you would like to drill down into specific packets and log certain variables, add the logging functionality to [scripts/icsnpp/s7comm/main.zeek](scripts/icsnpp/s7comm/main.zeek). The functions within [scripts/icsnpp/s7comm/main.zeek](scripts/icsnpp/s7comm/main.zeek) and [src/events.bif](src/events.bif) should prove to be a good guide on how to add new logging functionality.

This parser currently produces five log files. These log files are defined in [scripts/icsnpp/s7comm/main.zeek](scripts/icsnpp/s7comm/main.zeek).
* cotp.log
* s7comm.log
* s7comm_read_szl.log
* s7comm_upload_download.log
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
zeek -Cr icsnpp-s7comm/tests/traces/s7comm_plus_example.pcap icsnpp/s7comm
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
zeek -Cr icsnpp-s7comm/tests/traces/s7comm_plus_example.pcap icsnpp/s7comm
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

| Field             | Type      | Description                                                       |
| ----------------- |-----------|-------------------------------------------------------------------| 
| ts                | time      | Timestamp                                                         |
| uid               | string    | Unique ID for this Connection                                     |
| id                | conn_id   | Default Zeek Connection Info (IP addresses, ports)                |
| is_orig               | bool      | True if the packet is sent from the originator                |
| source_h              | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p              | port      | Source Port (see *Source and Destination Fields*)             |
| destination_h         | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p         | port      | Destination Port (see *Source and Destination Fields*)        |
| pdu_code          | string    | COTP PDU Type Code (in hex)                                       |
| pdu_name          | string    | COTP PDU Name                                                     |

### S7COMM Header Log (s7comm.log)

#### Overview

This log captures s7comm header information for every s7comm packet and logs it to **s7comm.log**.

#### Fields Captured

| Field                 | Type      | Description                                                   |
| --------------------- |-----------|---------------------------------------------------------------|
| ts                    | time      | Timestamp                                                     |
| uid                   | string    | Unique ID for this Connection                                 |
| id                    | conn_id   | Default Zeek Connection Info (IP addresses, ports)            |
| is_orig               | bool      | True if the packet is sent from the originator                |
| source_h              | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p              | port      | Source Port (see *Source and Destination Fields*)             |
| destination_h         | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p         | port      | Destination Port (see *Source and Destination Fields*)        |
| rosctr_code           | count     | Remote Operating Service Control Code (in hex)                |
| rosctr_name           | string    | Remote Operating Service Control Name                         |
| pdu_reference         | count     | Reference ID Used to Link Requests to Responses               |
| function_code         | string    | Parameter Function Code (in hex)                              |
| function_name         | string    | Parameter Function Name                                       |
| subfunction_code      | string    | User-Data Subfunction Code (in hex)                           |
| subfunction_name      | string    | User-Data Subfunction Name                                    |
| error_class           | string    | Error Class Name                                              |
| error_code            | string    | Error Code within Error Class                                 |

### S7COMM Read-SZL Log (s7comm_read_szl.log)

#### Overview

This log captures information for the common S7Comm Read-SZL function. This data is logged to **s7comm_read_szl.log**.

#### Fields Captured

| Field                 | Type      | Description                                                   |
| --------------------- |-----------|---------------------------------------------------------------|
| ts                    | time      | Timestamp                                                     |
| uid                   | string    | Unique ID for this Connection                                 |
| id                    | conn_id   | Default Zeek Connection Info (IP addresses, ports)            |
| is_orig               | bool      | True if the packet is sent from the originator                |
| source_h              | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p              | port      | Source Port (see *Source and Destination Fields*)             |
| destination_h         | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p         | port      | Destination Port (see *Source and Destination Fields*)        |
| pdu_reference         | count     | Reference ID Used to Link Requests to Responses               |
| method                | string    | Request or Response                                           |
| szl_id                | string    | SZL ID (in hex)                                               |
| szl_id_name           | string    | Meaning of SZL ID                                             |
| szl_index             | string    | SZL Index (in hex)                                            |
| return_code           | string    | Return Code (in hex)                                          |
| return_code_name      | string    | Meaning of Return Code                                        |

### S7COMM Upload-Download Log (s7comm_upload_download.log)

#### Overview

This log captures information for the S7Comm Upload and Download functions (see list below). This data is logged to **s7comm_upload_download.log**.:
* Start Upload
* Upload
* End Upload
* Request Download
* Download Block
* Download Ended

#### Fields Captured

| Field                  | Type      | Description                                                  |
| ---------------------- |-----------|--------------------------------------------------------------|
| ts                     | time      | Timestamp                                                    |
| uid                    | string    | Unique ID for this Connection                                |
| id                     | conn_id   | Default Zeek Connection Info (IP addresses, ports)           |
| is_orig               | bool      | True if the packet is sent from the originator                |
| source_h              | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p              | port      | Source Port (see *Source and Destination Fields*)             |
| destination_h         | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p         | port      | Destination Port (see *Source and Destination Fields*)        |
| rosctr                 | count     | Remote Operating Service Control                             |
| pdu_reference          | count     | Reference ID Used to Link Requests to Responses              |
| function_code          | count     | Parameter Function Code                                      |
| function_status        | count     | Function Status                                              |
| session_id             | count     | Session ID                                                   |
| blocklength            | count     | Length of Block to Upload/Download                           |
| filename               | string    | Filename of Block to Upload/Download                         |
| block_type             | string    | Block Type to Upload/Download                                |
| block_number           | string    | Block Number to Upload/Download                              |
| destination_filesystem | string    | Destination Filesystem of Upload/Download                    |

### S7COMM-PLUS Log (s7comm_plus.log)

#### Overview

This log captures s7comm-plus header information for every s7comm-plus packet and logs it to **s7comm_plus.log**.

#### Fields Captured

| Field                 | Type      | Description                                                   |
| --------------------- |-----------|---------------------------------------------------------------|
| ts                    | time      | Timestamp                                                     |
| uid                   | string    | Unique ID for this Connection                                 |
| id                    | conn_id   | Default Zeek Connection Info (IP addresses, ports)            |
| is_orig               | bool      | True if the packet is sent from the originator                |
| source_h              | address   | Source IP address (see *Source and Destination Fields*)       |
| source_p              | port      | Source Port (see *Source and Destination Fields*)             |
| destination_h         | address   | Destination IP address (see *Source and Destination Fields*)  |
| destination_p         | port      | Destination Port (see *Source and Destination Fields*)        |
| version               | count     | S7comm-plus Version                                           |
| opcode                | string    | Opcode Code (in hex)                                          |
| opcode_name           | string    | Opcode Name                                                   |
| function_code         | string    | Opcode Function Code (in hex)                                 |
| function_name         | string    | Opcode Function Name                                          |

### Source and Destination Fields

#### Overview

Zeek's typical behavior is to focus on and log packets from the originator and not log packets from the responder. However, most ICS protocols contain useful information in the responses, so the ICSNPP parsers log both originator and responses packets. Zeek's default behavior, defined in its `id` struct, is to never switch these originator/responder roles which leads to inconsistencies and inaccuracies when looking at ICS traffic that logs responses.

The default Zeek `id` struct contains the following logged fields:
* id.orig_h (Original Originator/Source Host)
* id.orig_p (Original Originator/Source Port)
* id.resp_h (Original Responder/Destination Host)
* id.resp_p (Original Responder/Destination Port)

Additionally, the `is_orig` field is a boolean field that is set to T (True) when the id_orig fields are the true originators/source and F (False) when the id_resp fields are the true originators/source.

To not break existing platforms that utilize the default `id` struct and `is_orig` field functionality, the ICSNPP team has added four new fields to each log file instead of changing Zeek's default behavior. These four new fields provide the accurate information regarding source and destination IP addresses and ports:
* source_h (True Originator/Source Host)
* source_p (True Originator/Source Port)
* destination_h (True Responder/Destination Host)
* destination_p (True Responder/Destination Port)

The pseudocode below shows the relationship between the `id` struct, `is_orig` field, and the new `source` and `destination` fields.

```
if is_orig == True
    source_h == id.orig_h
    source_p == id.orig_p
    destination_h == id.resp_h
    destination_p == id.resp_p
if is_orig == False
    source_h == id.resp_h
    source_p == id.resp_p
    destination_h == id.orig_h
    destination_p == id.orig_p
```

#### Example

The table below shows an example of these fields in the log files. The first log in the table represents a Modbus request from 192.168.1.10 -> 192.168.1.200 and the second log represents a Modbus reply from 192.168.1.200 -> 192.168.1.10. As shown in the table below, the `id` structure lists both packets as having the same originator and responder, but the `source` and `destination` fields reflect the true source and destination of these packets.

| id.orig_h    | id.orig_p | id.resp_h     | id.resp_p | is_orig | source_h      | source_p | destination_h | destination_p |
| ------------ | --------- |---------------|-----------|---------|---------------|----------|---------------|-------------- |
| 192.168.1.10 | 47785     | 192.168.1.200 | 502       | T       | 192.168.1.10  | 47785    | 192.168.1.200 | 502           |
| 192.168.1.10 | 47785     | 192.168.1.200 | 502       | F       | 192.168.1.200 | 502      | 192.168.1.10  | 47785         |

## S7COMM File Extraction

S7COMM contains two functions for sending and receiving files: Upload and Download-Block. This plugin will extract files sent via these two functions and pass the extracted files to Zeek's file analysis framework.

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
* [Synchrophasor](https://github.com/cisagov/icsnpp-synchrophasor)
    * Full Zeek protocol parser for Synchrophasor Data Transfer for Power Systems (C37.118)

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

Copyright 2023 Battelle Energy Alliance, LLC

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