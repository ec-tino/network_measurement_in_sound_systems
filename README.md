# network_measurement_in_sound_systems
This repo contains files used in a network measurement study: analyzing how stage sound networks handle heavy real-time data with low latency

## Main Project Questions:
- how many packets are transmitted within a specified time frame during a live show / no show?
- how do the sizes of the transmitted packets change depending on the network conditions?
    - Active network usage eg: during a live concert
    - Idle network eg: network without any live performance
    - Controlled network eg: intentionally controlling sound transmission for analysis.
 
## Phase 1: Capturing Packets Using tshark
- `capture.py` file contains code that builds a tshark command for capturing packets and writes the necessary fields (time, size, TP, IPs) of the captured packets into an output file that is later used for analysis.

- Run the command `sudo python capture.py --condition x --interface y --duration z` to start capturing packets going through interface y under condition x for z seconds.
    - X: takes on 3 values: `live` | `idle` | `research`
    - Y: specifies the interface you want to capture packets on. eg en1 for WiFi, en0 for Ethernet, etc.
    - Z: how long you want to capture packets. 

## Phase 2: Analyzing Patterns in Captured Packets

## Phase 3: Reporting Findings
