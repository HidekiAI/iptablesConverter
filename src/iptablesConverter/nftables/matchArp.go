package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Arp
arp match
	ptype <value>	Payload type
		arp ptype 0x0800
	htype <value>	Header type
		arp htype 1
		arp htype != 33-45
		arp htype { 33, 55, 67, 88}
	hlen <length>	Header Length
		arp hlen 1
		arp hlen != 33-45
		arp hlen { 33, 55, 67, 88}
	plen <length>	Payload length
		arp plen 1
		arp plen != 33-45
		arp plen { 33, 55, 67, 88}
	operation <value>
		arp operation {nak, inreply, inrequest, rreply, rrequest, reply, request}

*/
