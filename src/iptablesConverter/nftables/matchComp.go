package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Comp
comp match
	nexthdr <protocol>	Next header protocol (Upper layer protocol)
		comp nexthdr != esp
		comp nexthdr {esp, ah, comp, udp, udplite, tcp, tcp, dccp, sctp}
	flags <flags>	Flags
		comp flags 0x0
		comp flags != 0x33-0x45
		comp flags {0x33, 0x55, 0x67, 0x88}
	cpi <value>	Compression Parameter Index
		comp cpi 22
		comp cpi != 33-45
		comp cpi {33, 55, 67, 88}

*/
