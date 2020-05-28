package main

import (
	"context"
	"fmt"
	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		panic(color.RedString("%v needs a path of a pcap file passed.", os.Args[0]))
	} else if len(os.Args) > 2 {
		panic(color.RedString("%v ONLY needs a path of a pcap file passed.", os.Args[0]))
	} else if len(os.Args) == 2 {
		if handle, err := pcap.OpenOffline(os.Args[1]); err != nil {
			panic(err)
		} else {
			fmt.Println("Opened the pcap file:", color.YellowString(os.Args[1]))
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			var record_collection []dns_record
			for {
				packet, err := packetSource.NextPacket()
				if err == io.EOF {
					break
				} else if err != nil {
					panic(err)
				}
				if isDNS(packet) && isDNSAnswer(packet) {
					record_collection = appendRecordToCollection(record_collection, handlePacket(packet))
				}
			}
			printCollection(reverseLookupCollection(record_collection))
		}
	}
}

func handlePacket(packet gopacket.Packet) dns_record {
	dns_pkt, _ := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	var (
		pkt_name string
		pkt_ips  []net.IP
	)
	for i, answer := range dns_pkt.Answers {
		if i == 0 {
			pkt_name = string(answer.Name)
		}
		pkt_ips = append(pkt_ips, answer.IP)
	}
	pkt_reverse := make([][]string, len(pkt_ips))
	return dns_record{name: pkt_name, ips: pkt_ips, reverse: pkt_reverse}
}

func isDNS(packet gopacket.Packet) bool {
	if packet.Layer(layers.LayerTypeDNS) != nil {
		return true
	}
	return false
}

func isDNSAnswer(packet gopacket.Packet) bool {
	dns_pkt, _ := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	if len(dns_pkt.Answers) != 0 {
		return true
	}
	return false
}

func appendRecordToCollection(collection []dns_record, record dns_record) []dns_record {
	for i := range collection {
		if collection[i].name == record.name {
			for j := range record.ips {
				found := false
				for k := range collection[i].ips {
					if record.ips[j].String() == collection[i].ips[k].String() {
						found = true
						break
					}
				}
				if !found {
					collection[i].ips = append(collection[i].ips, record.ips[j])
					collection[i].reverse = append(collection[i].reverse, record.reverse[j])
				}
			}
			return collection
		}
	}
	collection = append(collection, record)
	return collection
}

func reverseLookupCollection(collection []dns_record) []dns_record {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}
	for i := range collection {
		for j := range collection[i].ips {
			reversed, _ := resolver.LookupAddr(context.Background(), collection[i].ips[j].String())
			collection[i].reverse[j] = reversed
		}
	}
	return collection
}

func printCollection(collection []dns_record) {
	for i := range collection {
		for j := range collection[i].ips {
			for k := range collection[i].reverse[j] {
				print(color.CyanString(collection[i].name))
				print(color.HiWhiteString(" -> "))
				print(color.HiYellowString(collection[i].ips[j].String()))
				print(color.HiWhiteString(" -> "))
				if strings.Contains(strings.ToUpper(collection[i].name), strings.ToUpper(collection[i].reverse[j][k])) || strings.Contains(strings.ToUpper(collection[i].reverse[j][k]), strings.ToUpper(collection[i].name)) {
					print(color.GreenString(collection[i].reverse[j][k]))
				} else {
					print(color.RedString(collection[i].reverse[j][k]))
				}
				print("\n")
			}
		}
	}
}

type dns_record struct {
	name    string
	ips     []net.IP
	reverse [][]string
}
