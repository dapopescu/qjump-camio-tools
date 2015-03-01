REQUIREMENTS
============

Cake
-----
To build it, you must have the "cake" build system installed. 
You can obtain cake from https://github.com/Zomojo/Cake
To insall cake, follow the instructions in "INSTALL".

CamIO 1.0
---------
You can obtain the camio 1.0 library from 
https://github.com/mgrosvenor/camio1.0
To build camio, run "build.sh" in the root directory.


BUILDING
========
To build a debug version run:
./build.sh

To build a release version run:
./build.sh --variant=release

RUNNING
=======


packet_gen:

|Mode     |Short|Long Option    | Description                                                                  |
|---------|-----|---------------|------------------------------------------------------------------------------|
|Required | -i  |--interface    |   - Interface name to generate packets on eg eth0 |
|Required | -s  |--src          |   - Source trailing IP number eg 106 for 10.10.0.106 | 
|Required | -m  |--mac          |   - Destination MAC address number as a hex string eg 0x90E2BA27FBE0 |
|Required | -d  |--dst          |   - Destination trailing IP number eg 112 for 10.10.0.102 |
|Optional | -n  |--num-pkts     |   - Number of packets to send before stopping. -1=inf [-1] |
|Optional | -I  |--init-seq     |   - Initial sequence number to use [0] |
|Optional | -D  |--delay        |   - How long to delay in between sending individual packets. [0] |
|Optional | -W  |--wait         |   - How long to delay in nanoseconds. between sending bursts [0] |
|Optional | -l  |--length       |   - Length of the entire packet in bytes [1514] |
|Optional | -L  |--listener     |   - Description of a command lister eg udp:192.168.0.1:2000 [NULL] |
|Optional | -p  |--pid          |   - Packet generator ID. Which messages to listen to. |
|Optional | -u  |--use-seq      |   - Use sequence numbers in packets [true] |
|Optional | -b  |--burst        |   - How many packets to send in each burst [0] |
|Optional | -o  |--offset       |   - How long in microseconds to sleep before beginning to send |
|Flag     | -V  |--verbose      |   - Verbose output messages |
|Optional | -t  |--timeout      |   - time to run for [60s] |
|Optional | -S  |--stop         |   - How many packets to send before stopping for a break [0] |
|Flag     | -h  |--help         |   - Print this help message |

Generates packets using netmap at up to linerate for all packet sizes.

