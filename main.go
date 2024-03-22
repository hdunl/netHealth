package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	_ "os"
	"sort"
	"strconv"
	_ "strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type NetworkReport struct {
	Latency                map[string]time.Duration
	PacketLoss             map[string]float64
	Jitter                 map[string]time.Duration
	PrevTimestamp          map[string]time.Time
	Throughput             map[string]uint64
	PacketCount            map[string]uint64
	ProtocolDistribution   map[string]uint64
	TCPFlagsDistribution   map[string]uint64
	PacketSizeDistribution map[string]uint64
	FragmentationRate      map[string]float64
	StartTime              time.Time
	EndTime                time.Time
	InterfaceName          string
	SnapshotLength         int32
	PromiscuousMode        bool
	TimeoutMilliseconds    int
	TotalPacketsCaptured   uint64
	TotalPacketsAnalyzed   uint64
	TotalPacketsDropped    uint64
	TotalPacketsIfDropped  uint64
	TotalBytes             uint64
	TotalPacketsPerSecond  float64
	TotalBytesPerSecond    float64
	AveragePacketSize      float64
	mutex                  sync.Mutex
}

func main() {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Available network interfaces:")
	for i, iface := range interfaces {
		fmt.Printf("%d. %s (%s)\n", i+1, iface.Name, iface.Description)
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter the number of the interface to monitor: ")
	interfaceInput, _ := reader.ReadString('\n')
	interfaceInput = strings.TrimSpace(interfaceInput)
	selectedIndex, err := strconv.Atoi(interfaceInput)
	if err != nil {
		log.Fatal("Invalid interface number")
	}

	if selectedIndex < 1 || selectedIndex > len(interfaces) {
		log.Fatal("Invalid interface selection")
	}

	fmt.Print("Enter the monitoring duration in seconds: ")
	durationInput, _ := reader.ReadString('\n')
	durationInput = strings.TrimSpace(durationInput)
	duration, err := strconv.Atoi(durationInput)
	if err != nil {
		log.Fatal("Invalid duration")
	}

	selectedInterface := interfaces[selectedIndex-1]
	handle, err := pcap.OpenLive(selectedInterface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	report := monitorNetworkHealth(handle, duration)

	printReport(report)
}

func monitorNetworkHealth(handle *pcap.Handle, duration int) *NetworkReport {
	report := &NetworkReport{
		Latency:                make(map[string]time.Duration),
		PacketLoss:             make(map[string]float64),
		Jitter:                 make(map[string]time.Duration),
		PrevTimestamp:          make(map[string]time.Time),
		Throughput:             make(map[string]uint64),
		PacketCount:            make(map[string]uint64),
		ProtocolDistribution:   make(map[string]uint64),
		TCPFlagsDistribution:   make(map[string]uint64),
		PacketSizeDistribution: make(map[string]uint64),
		FragmentationRate:      make(map[string]float64),
		StartTime:              time.Now(),
		InterfaceName:          handle.LinkType().String(),
		SnapshotLength:         int32(handle.SnapLen()),
		PromiscuousMode:        true,
		TimeoutMilliseconds:    10,
		TotalPacketsCaptured:   0,
		TotalPacketsAnalyzed:   0,
		TotalPacketsDropped:    0,
		TotalPacketsIfDropped:  0,
		TotalBytes:             0,
		TotalPacketsPerSecond:  0,
		TotalBytesPerSecond:    0,
		AveragePacketSize:      0,
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	stopTimer := time.AfterFunc(time.Duration(duration)*time.Second, func() {
		handle.Close()
	})
	defer stopTimer.Stop()

	var wg sync.WaitGroup
	for packet := range packets {
		wg.Add(1)
		go func(p gopacket.Packet) {
			defer wg.Done()
			analyzePacket(report, p)
		}(packet)
	}
	wg.Wait()

	report.EndTime = time.Now()
	calculateStatistics(report)
	return report
}

func analyzePacket(report *NetworkReport, packet gopacket.Packet) {
	report.mutex.Lock()
	defer report.mutex.Unlock()

	report.TotalPacketsCaptured++
	report.TotalPacketsAnalyzed++

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)
	srcAddr := ip.SrcIP.String()
	dstAddr := ip.DstIP.String()

	report.PacketCount[srcAddr]++
	report.PacketCount[dstAddr]++

	if ip.Protocol == layers.IPProtocolICMPv4 {
		report.ProtocolDistribution["ICMP"]++
		icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
		if icmpLayer == nil {
			return
		}
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
			report.Latency[srcAddr] = time.Now().Sub(packet.Metadata().CaptureInfo.Timestamp)
			report.PacketLoss[srcAddr]++
		} else if icmp.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
			report.Latency[dstAddr] = time.Now().Sub(packet.Metadata().CaptureInfo.Timestamp)
			if _, ok := report.PacketLoss[dstAddr]; ok {
				if report.PacketLoss[dstAddr] > 0 {
					report.PacketLoss[dstAddr]--
				}
			}
		}
	}

	if ip.Protocol == layers.IPProtocolTCP {
		report.ProtocolDistribution["TCP"]++
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			return
		}
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN && !tcp.ACK {
			report.TCPFlagsDistribution["SYN"]++
		} else if tcp.SYN && tcp.ACK {
			report.TCPFlagsDistribution["SYN-ACK"]++
		} else if tcp.FIN {
			report.TCPFlagsDistribution["FIN"]++
		} else if tcp.RST {
			report.TCPFlagsDistribution["RST"]++
		}
	}

	if ip.Protocol == layers.IPProtocolUDP {
		report.ProtocolDistribution["UDP"]++
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			return
		}
		_, _ = udpLayer.(*layers.UDP)
		timestamp := packet.Metadata().CaptureInfo.Timestamp
		if prevTimestamp, ok := report.PrevTimestamp[srcAddr]; ok {
			report.Jitter[srcAddr] = timestamp.Sub(prevTimestamp)
		}
		report.PrevTimestamp[srcAddr] = timestamp

		if prevTimestamp, ok := report.PrevTimestamp[dstAddr]; ok {
			report.Jitter[dstAddr] = timestamp.Sub(prevTimestamp)
		}
		report.PrevTimestamp[dstAddr] = timestamp
	}

	report.Throughput[srcAddr] += uint64(len(packet.Data()))
	report.Throughput[dstAddr] += uint64(len(packet.Data()))

	packetSize := len(packet.Data())
	switch {
	case packetSize < 64:
		report.PacketSizeDistribution["0-64"]++
	case packetSize < 128:
		report.PacketSizeDistribution["64-128"]++
	case packetSize < 256:
		report.PacketSizeDistribution["128-256"]++
	case packetSize < 512:
		report.PacketSizeDistribution["256-512"]++
	case packetSize < 1024:
		report.PacketSizeDistribution["512-1024"]++
	case packetSize < 1500:
		report.PacketSizeDistribution["1024-1500"]++
	default:
		report.PacketSizeDistribution["1500+"]++
	}

	if ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0 {
		report.FragmentationRate[srcAddr]++
		report.FragmentationRate[dstAddr]++
	}

	report.TotalBytes += uint64(packetSize)
}

func calculateStatistics(report *NetworkReport) {
	duration := report.EndTime.Sub(report.StartTime)
	durationSeconds := duration.Seconds()

	report.TotalPacketsDropped = report.TotalPacketsCaptured - report.TotalPacketsAnalyzed
	report.TotalPacketsPerSecond = float64(report.TotalPacketsCaptured) / durationSeconds
	report.TotalBytesPerSecond = float64(report.TotalBytes) / durationSeconds
	report.AveragePacketSize = float64(report.TotalBytes) / float64(report.TotalPacketsCaptured)

	for addr := range report.FragmentationRate {
		report.FragmentationRate[addr] = report.FragmentationRate[addr] / float64(report.PacketCount[addr]) * 100
	}

	for addr := range report.PacketLoss {
		sentPackets := uint64(report.PacketLoss[addr])
		receivedPackets := report.PacketCount[addr]
		if sentPackets > 0 {
			report.PacketLoss[addr] = float64(sentPackets-receivedPackets) / float64(sentPackets) * 100
		} else {
			report.PacketLoss[addr] = 0
		}
	}
}

func printReport(report *NetworkReport) {
	fmt.Printf("Network Health Report\n\n")
	fmt.Printf("Start Time: %s\n", report.StartTime.Format(time.RFC3339))
	fmt.Printf("End Time: %s\n", report.EndTime.Format(time.RFC3339))
	fmt.Printf("Duration: %s\n", report.EndTime.Sub(report.StartTime))
	fmt.Printf("Interface Name: %s\n", report.InterfaceName)
	fmt.Printf("Snapshot Length: %d\n", report.SnapshotLength)
	fmt.Printf("Promiscuous Mode: %t\n", report.PromiscuousMode)
	fmt.Printf("Timeout (ms): %d\n\n", report.TimeoutMilliseconds)

	fmt.Printf("Total Packets Captured: %d\n", report.TotalPacketsCaptured)
	fmt.Printf("Total Packets Analyzed: %d\n", report.TotalPacketsAnalyzed)
	fmt.Printf("Total Packets Dropped: %d\n", report.TotalPacketsDropped)
	fmt.Printf("Total Packets Interface Dropped: %d\n", report.TotalPacketsIfDropped)
	fmt.Printf("Total Bytes Captured: %d\n", report.TotalBytes)
	fmt.Printf("Total Packets per Second: %.2f\n", report.TotalPacketsPerSecond)
	fmt.Printf("Total Bytes per Second: %.2f\n", report.TotalBytesPerSecond)
	fmt.Printf("Average Packet Size: %.2f bytes\n\n", report.AveragePacketSize)

	fmt.Println("Latency Report:")
	sortedLatency := sortMapByDuration(report.Latency)
	for _, addr := range sortedLatency {
		fmt.Printf("%s: %s\n", addr, report.Latency[addr])
	}
	fmt.Println()

	fmt.Println("Packet Loss Report:")
	sortedPacketLoss := sortMapByFloat64(report.PacketLoss)
	for _, addr := range sortedPacketLoss {
		fmt.Printf("%s: %.2f%%\n", addr, report.PacketLoss[addr])
	}
	fmt.Println()

	fmt.Println("Jitter Report:")
	sortedJitter := sortMapByDuration(report.Jitter)
	for _, addr := range sortedJitter {
		fmt.Printf("%s: %s\n", addr, report.Jitter[addr])
	}
	fmt.Println()

	fmt.Println("Throughput Report:")
	sortedThroughput := sortMapByUint64(report.Throughput)
	for _, addr := range sortedThroughput {
		fmt.Printf("%s: %d bytes/sec\n", addr, report.Throughput[addr])
	}
	fmt.Println()

	fmt.Println("Packet Count Report:")
	sortedPacketCount := sortMapByUint64(report.PacketCount)
	for _, addr := range sortedPacketCount {
		fmt.Printf("%s: %d packets\n", addr, report.PacketCount[addr])
	}
	fmt.Println()

	fmt.Println("Protocol Distribution:")
	sortedProtocolDistribution := sortMapByUint64(report.ProtocolDistribution)
	for _, protocol := range sortedProtocolDistribution {
		fmt.Printf("%s: %d packets\n", protocol, report.ProtocolDistribution[protocol])
	}
	fmt.Println()

	fmt.Println("TCP Flags Distribution:")
	sortedTCPFlagsDistribution := sortMapByUint64(report.TCPFlagsDistribution)
	for _, flag := range sortedTCPFlagsDistribution {
		fmt.Printf("%s: %d packets\n", flag, report.TCPFlagsDistribution[flag])
	}
	fmt.Println()

	fmt.Println("Packet Size Distribution:")
	sortedPacketSizeDistribution := sortMapByUint64(report.PacketSizeDistribution)
	for _, sizeRange := range sortedPacketSizeDistribution {
		fmt.Printf("%s: %d packets\n", sizeRange, report.PacketSizeDistribution[sizeRange])
	}
	fmt.Println()

	fmt.Println("Fragmentation Rate Report:")
	sortedFragmentationRate := sortMapByFloat64(report.FragmentationRate)
	for _, addr := range sortedFragmentationRate {
		fmt.Printf("%s: %.2f%%\n", addr, report.FragmentationRate[addr])
	}
}

func sortMapByDuration(m map[string]time.Duration) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return m[keys[i]] < m[keys[j]]
	})
	return keys
}

func sortMapByFloat64(m map[string]float64) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return m[keys[i]] < m[keys[j]]
	})
	return keys
}

func sortMapByUint64(m map[string]uint64) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return m[keys[i]] < m[keys[j]]
	})
	return keys
}
