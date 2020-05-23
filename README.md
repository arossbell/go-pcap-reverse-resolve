Curious to see what this would look like in Go.

Provide it a PCAP file, it finds all DNS answers and then performs a reverse DNS lookup on those answers.

Outputs the following after the reverse lookup:

`Original Lookup Name -> DNS Answer IP Address -> Reverse DNS Lookup Result`

Colored output displays green at the reverse DNS result(s) if the original name matches the result(s). Red otherwise.

(The intent of this is to have a *general* look at possible CDNs.)

**NOTE:** Using a custom resolver: 8.8.8.8

###Usage:
`./pcap-reverse-resolve <PCAP path>`

###Build:
`go build pcap-reverse-resolve.go`

(Build requires libpcap: `apt install libpcap-dev` on Debian/Ubuntu)
