# Packet Sniffer

A simple packet sniffing program written in C that captures and displays IP packets on a specified network interface. This program utilizes the `pcap` library to capture live network traffic.

## Features

- Capture IP packets from a specified network interface.
- Display source and destination IP addresses for each captured packet.
- Support for promiscuous mode.
- User-friendly interface for selecting network devices.

## Requirements

- C compiler (e.g., `gcc`)
- `libpcap` library

## Installation

1. **Install libpcap** (if not already installed):

   On Ubuntu/Debian:
   ```bash
   sudo apt-get install libpcap-dev
   ```

2. **Compile Sniffer**
   ```bash
   make
   ```
