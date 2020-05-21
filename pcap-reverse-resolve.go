package main

import (
	//"reflect" // Good for finding type: `println(reflect.TypeOf(VARIABLE).String())`
	"os"
	"io"
	"fmt"
	"net"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"github.com/fatih/color"
)

/*   GRAVEYARD CODE
	fmt.Printf("%v ... %v ... %v\n", color.MagentaString("Test!"), color.HiWhiteString("then another"), color.HiYellowString("ANOTHER!"))


*/


func main() {
	if len(os.Args) < 2 {
		panic(color.RedString("%v needs a path of a pcap file passed.", os.Args[0]))
	} else if len(os.Args) > 2 {
		panic(color.RedString("%v ONLY needs a path of a pcap file passed.", os.Args[0]))
	} else if len(os.Args) == 2 {
		if handle, err := pcap.OpenOffline(os.Args[1]); err != nil {
			panic(err)
		} else {
			fmt.Println("Opened the pcap file:", os.Args[1])
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
			record_collection = reverseLookupCollection(removeNilIPs(record_collection))
			println("Got here. First record: ", record_collection[0].name)
		}
	}
}

func handlePacket(packet gopacket.Packet) dns_record {
	dns_pkt, _ := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	var (
		pkt_name string
		pkt_ips []net.IP
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
	if packet.Layer(layers.LayerTypeDNS) != nil { return true }
	return false
}

func isDNSAnswer(packet gopacket.Packet) bool {
	dns_pkt, _ := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
	if len(dns_pkt.Answers) != 0 { return true }
	return false
}

// This function should help de-duplicate -- especially the IPv4 vs IPv6 responses.
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

// Not sure where they're coming from, but I'm dropping them.
func removeNilIPs(collection []dns_record) []dns_record {
	for i := range collection {
		for j := range collection[len(collection) - (i+1)].ips {
			if collection[len(collection) - (i+1)].ips[len(collection[len(collection) - (i+1)].ips) - (j+1)] == nil {
				collection[len(collection) - (i+1)].ips = append(collection[len(collection) - (i+1)].ips[:len(collection[len(collection) - (i+1)].ips) - (j+1)], collection[len(collection) - (i+1)].ips[len(collection[len(collection) - (i+1)].ips) - (j+1) + 1:]...)
				collection[len(collection) - (i+1)].reverse = append(collection[len(collection) - (i+1)].reverse[:len(collection[len(collection) - (i+1)].reverse) - (j+1)], collection[len(collection) - (i+1)].reverse[len(collection[len(collection) - (i+1)].reverse) - (j+1) + 1:]...)
			}
		}
	}
	return collection
}

func reverseLookupCollection(collection []dns_record) []dns_record {
	for i := range collection {
		for j := range collection[i].ips {
			reversed, _ := net.LookupAddr(collection[i].ips[j].String())
			collection[i].reverse[j] = reversed
		}
	}
	return collection
}

type dns_record struct {
	name string
	ips []net.IP
	reverse [][]string
}

