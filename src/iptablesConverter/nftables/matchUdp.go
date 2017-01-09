package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Udp
udp match
	dport <destination port>	Destination port
		udp dport 22
		udp dport != 33-45
		udp dport { 33-55 }
		udp dport {telnet, http, https }
		udp dport vmap { 22 : accept, 23 : drop }
		udp dport vmap { 25:accept, 28:drop }
	sport < source port>	Source port
		udp sport 22
		udp sport != 33-45
		udp sport { 33, 55, 67, 88}
		udp sport { 33-55}
		udp sport vmap { 25:accept, 28:drop }
		udp sport 1024 tcp dport 22
	length <length>	Total packet length
		udp length 6666
		udp length != 50-65
		udp length { 50, 65 }
		udp length { 35-50 }
	checksum <checksum>	UDP checksum
		udp checksum 22
		udp checksum != 33-45
		udp checksum { 33, 55, 67, 88 }
		udp checksum { 33-55 }

*/