package handle

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"strings"
	"net"
	"github.com/google/gopacket/layers"
	"log"
)

type SniffData struct {
	SrcIP   net.IP
	SrcPort int
	DesIP   net.IP
	DesPort int
	Payload int
}

type PcapSniffer struct {
	Handle       *pcap.Handle
	PacketSource *gopacket.PacketSource
	Parser       *gopacket.DecodingLayerParser
	InFace       net.Interface
	Decoded      []gopacket.LayerType
	Eth          layers.Ethernet
	Ip4          layers.IPv4
	Tcp          layers.TCP
	//Payload gopacket.Payload
	IsRunning bool
}

func NewPcapSniffer() *PcapSniffer {

	sniffer := PcapSniffer{}
	sniffer.Parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &sniffer.Ip4, &sniffer.Tcp, &sniffer.Eth)
	sniffer.IsRunning = true
	return &sniffer
}

func (s *PcapSniffer) Open() error {

	var devName string

	//get all sniffable devices
	dev, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}

	//get unicast interface
	if s.InFace, err = defaultIface(); err != nil {
		return err
	}

	//find unicast device
	addr, err := s.InFace.Addrs()
	if err != nil {
		return err
	}

	for _, curr := range dev {
		if len(curr.Addresses) !=0 && strings.Contains(addr[0].String(), curr.Addresses[0].IP.String()) {
			devName = curr.Name
			break
		}
	}

	if len(devName) == 0 {
		log.Fatal("No proper device for sniffing")
	}

	s.Handle, err = pcap.OpenLive(devName, int32(s.InFace.MTU)+100, true, pcap.BlockForever)
	if err != nil {
		return err
	}

	//open endless packet source
	s.PacketSource = gopacket.NewPacketSource(s.Handle, s.Handle.LinkType())

	return nil
}

func (s *PcapSniffer) Close() {
	s.Handle.Close()
}

func (s *PcapSniffer) ReadPacket() (data []byte, ci gopacket.CaptureInfo, err error) {
	return s.Handle.ZeroCopyReadPacketData()
}

func (s *PcapSniffer) Listen(ch chan SniffData) {

	for packet := range s.PacketSource.Packets() {

		capture := SniffData{}

		s.Parser.DecodeLayers(packet.Data(), &s.Decoded)

		for _, layerType := range s.Decoded {

			switch layerType {

			case layers.LayerTypeEthernet:

			case layers.LayerTypeTCP:

				capture.SrcPort = int(s.Tcp.SrcPort)
				capture.DesPort = int(s.Tcp.DstPort)
				capture.Payload = len(s.Tcp.Payload)

			case layers.LayerTypeIPv4:

				capture.SrcIP = s.Ip4.SrcIP
				capture.DesIP = s.Ip4.DstIP

			}
		}

		//catch TCP payload data
		if capture.Payload > 0 {
			ch <- capture
		}
		//
		if !s.IsRunning {
			return
		}
	}
}

func defaultIface() (inter net.Interface, err error) {
	ifaces, _ := net.Interfaces()

	for _, candidate := range ifaces {
		f := candidate.Flags
		if (f&net.FlagUp != 0) && (f&net.FlagLoopback == 0) {
			inter = candidate
			return
		}
	}
	err = fmt.Errorf("no valid interface for sniffing")
	return
}
