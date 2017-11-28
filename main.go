package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"net"
	"os"
	"encoding/json"
	"fmt"
	"strings"
)

func main() {

	type sniff struct {
		SrcIP   net.IP
		SrcPort int
		DesIP   net.IP
		DesPort int
		Payload int
	}

	var handle *pcap.Handle
	var devName string

	defer handle.Close()

	//get all sniffable devices
	dev, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	//get unicast interface
	iface, err := defaultIface()
	if err != nil {
		panic(err)
	}

	//find unicast device
	for _, curr := range dev {
		if strings.Contains(iface[0].String(), curr.Addresses[0].IP.String()) {
			devName = curr.Name
		}
	}

	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &ip4, &tcp, &eth)
	decoded := []gopacket.LayerType{}

	f, err := os.Create("sniff.txt")
	defer f.Close()

	handle, err = pcap.OpenLive(devName, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {

			if err := parser.DecodeLayers(packet.Data(), &decoded); err != nil {
				sn := sniff{}
				for _, layerType := range decoded {
			
					switch layerType {
					case layers.LayerTypeTCP:

						sn.SrcPort = int(tcp.SrcPort)
						sn.DesPort = int(tcp.DstPort)
						sn.Payload = len(tcp.Payload)

					case layers.LayerTypeIPv4:

						sn.SrcIP = ip4.SrcIP
						sn.DesIP = ip4.DstIP
					}

				}

				if sn.Payload > 0 {
					st, err := json.Marshal(sn)
					if err != nil {
						panic(err)
					}
					f.Write(st)
					f.WriteString("\n")
				}
			}
		}
	}
}

func defaultIface() ([]net.Addr, error) {
	ifaces, _ := net.Interfaces()

	for _, candidate := range ifaces {
		f := candidate.Flags
		if (f&net.FlagUp != 0) && (f&net.FlagLoopback == 0) {
			addr, err := candidate.Addrs()
			return []net.Addr(addr), err
		}
	}
	return nil, fmt.Errorf("No valid interface for sniffing")
}
