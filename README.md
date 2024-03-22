# netHealth

This is a Go program that monitors network health by capturing and analyzing network packets using the `gopacket` library. It provides insights into various network metrics such as latency, packet loss, jitter, throughput, packet count, protocol distribution, TCP flags distribution, packet size distribution, and fragmentation rate.

## Features

- Captures network packets from a selected network interface
- Analyzes captured packets to calculate network health metrics
- Generates a detailed network health report
- Supports IPv4, TCP, UDP, and ICMP protocols
- Calculates latency, packet loss, jitter, and throughput for each source and destination IP address
- Provides protocol distribution, TCP flags distribution, and packet size distribution
- Calculates fragmentation rate for each IP address
- Sorts and presents the report data in a readable format

## Prerequisites

- Go programming language installed
- `gopacket` library installed (`go get github.com/google/gopacket`)

## Usage

1. Clone the repository or download the source code.
2. Open a terminal and navigate to the project directory.
3. Run the program using the command: `go run main.go`.
4. Select the network interface to monitor by entering the corresponding number.
5. Specify the monitoring duration in seconds.
6. The program will start capturing and analyzing network packets for the specified duration.
7. Once the monitoring is complete, a detailed network health report will be displayed in the terminal.

## Network Health Report

The generated network health report includes the following information:

- Start time and end time of the monitoring session
- Duration of the monitoring session
- Interface name, snapshot length, promiscuous mode, and timeout settings
- Total packets captured, analyzed, dropped, and interface dropped
- Total bytes captured, packets per second, bytes per second, and average packet size
- Latency report for each source and destination IP address
- Packet loss report for each source and destination IP address
- Jitter report for each source and destination IP address
- Throughput report for each source and destination IP address
- Packet count report for each source and destination IP address
- Protocol distribution (ICMP, TCP, UDP)
- TCP flags distribution (SYN, SYN-ACK, FIN, RST)
- Packet size distribution
- Fragmentation rate report for each source and destination IP address

## Customization

You can customize the program according to your requirements:

- Modify the `analyzePacket` function to add or remove specific analysis logic
- Adjust the packet size ranges in the `analyzePacket` function to suit your needs
- Customize the `printReport` function to change the format or add additional information to the report
