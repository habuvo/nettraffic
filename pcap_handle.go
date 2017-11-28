package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// libpcap version of the gopacket library
type PcapSniffer struct {
	handle *pcap.Handle
}

func (s *PcapSniffer) Open() error {
	// Capture settings
	const (
		// Max packet length
		snaplen int32 = 65536
		// Set the interface in promiscuous mode
		promisc bool = true
		// Timeout duration
		filter string = "ip"
	)

	// Open the interface
	handle, err := pcap.OpenLive("Ethernet", snaplen, promisc, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("Error opening pcap handle: %s", err)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("Error setting BPF filter: %s", err)
	}
	s.handle = handle

	return nil
}

func (s *PcapSniffer) Close() {
	s.handle.Close()
}

func (s *PcapSniffer) ReadPacket() (data []byte, ci gopacket.CaptureInfo, err error) {
	return s.handle.ZeroCopyReadPacketData()
}