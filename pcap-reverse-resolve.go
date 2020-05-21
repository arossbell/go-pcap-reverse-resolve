package main

import (
	//"reflect" // Good for finding type: `println(reflect.TypeOf(VARIABLE).String())`
	"os"
	"io"
	"fmt"
	//"net"
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
			for {
				packet, err := packetSource.NextPacket()
				if err == io.EOF {
					break
				} else if err != nil {
					panic(err)
				}
				handlePacket(packet)
			}
		}
	}
}

func handlePacket(packet gopacket.Packet) /*(string, []string)*/ {
	if isDNS(packet) {
		dns_pkt, _ := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
		if len(dns_pkt.Answers) != 0 {
			for _, answer := range dns_pkt.Answers {
				print(string(answer.Name), " = ", string(answer.IP.String()), "; ")
			}
			print("\n")
		}
	}
}

func isDNS(packet gopacket.Packet) bool {
	if packet.Layer(layers.LayerTypeDNS) != nil { return true }
	return false
}

