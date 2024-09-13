# In-Network Detection of ICMPv6 DDoS Attacks using P4

This repository contains the research, code, and final report for the project on detecting and mitigating ICMPv6 DDoS attacks. The project focuses on using P4 programming to build a defense mechanism on a programmable switch, combined with probabilistic data structures such as Bloom filters and Count-Min Sketch (CMS) to analyze traffic patterns in real time.

## Project Overview

**Objective**: Implement an efficient system for real-time detection and mitigation of ICMPv6 Neighbor Discovery Protocol (NDP) attacks using programmable network devices and advanced data structures.

**Technologies**:
- **P4 Language**: To define packet processing logic on programmable switches.
- **BMv2 Switch**: To simulate the programmable switch environment.
- **Bloom Filters and Count-Min Sketch**: To track and analyze packet traffic.
- **Scapy Library**: For simulating realistic ICMPv6 attack traffic.

## Files in the Repository

- `attack.py`: Python script using the Scapy library to simulate ICMPv6 attack traffic. This script sends attack packets to the target hosts in the network.
- `compile.sh`: A script to ease the process of compiling the P4 program for the BMv2 switch.
- `links.sh`: A script that initializes virtual hosts and connects them to the virtual BMv2 switch to simulate the network environment.
- `p4_nsaf.p4`: The P4 program responsible for detecting and mitigating ICMPv6 DDoS attacks using probabilistic methods.
- `p4_nsaf.json`: The compiled output of the P4 program, ready for deployment on the BMv2 switch.
- `power.py`: A Python script to facilitate the initialization of the BMv2 switch for testing and running the P4 program.

## Setup

### Prerequisites

1. **P4 Development Environment**: Ensure you have a working P4 environment. Install the BMv2 software switch and P4 compiler.
2. **Python 3.x**: Required for running `attack.py` with Scapy.

### Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/username/repository-name.git
    ```

2. Install the dependencies:
   - Install the P4 environment from [P4lang tutorials](https://github.com/p4lang/tutorials).
   - Install Python dependencies for running `attack.py`:

    ```bash
    pip install scapy
    ```

3. Compile the P4 program:

    ```bash
    ./compile.sh
    ```

4. Set up the virtual hosts and the BMv2 switch:

    ```bash
    ./links.sh
    ./power.py
    ```

5. Run the attack simulation:

    ```bash
    python3 attack.py
    ```

## Usage

- **Attack Simulation**: Run `attack.py` to simulate the ICMPv6 attack. Modify the script for different attack patterns.
- **Switch Initialization**: Use `power.py` to start the BMv2 switch, which will process traffic based on the P4 program.
- **Compilation**: The `compile.sh` script compiles the P4 program and generates the `p4_nsaf.json` file, which is loaded into the BMv2 switch.

## Final Report

The full research report, detailing the methodology, implementation, and evaluation, is available in the `report` folder. It covers:
- ICMPv6 NDP attacks background
- Defense mechanism design using P4
- Experiment results and evaluation
- Future work
