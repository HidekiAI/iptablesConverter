package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Udplite
udplite match
	dport <destination port>	Destination port
		udplite dport 22
		udplite dport != 33-45
		udplite dport { 33-55 }
		udplite dport {telnet, http, https }
		udplite dport vmap { 22 : accept, 23 : drop }
		udplite dport vmap { 25:accept, 28:drop }
	sport < source port>	Source port
		udplite sport 22
		udplite sport != 33-45
		udplite sport { 33, 55, 67, 88}
		udplite sport { 33-55}
		udplite sport vmap { 25:accept, 28:drop }
		udplite sport 1024 tcp dport 22
	checksum <checksum>	Checksum
		udplite checksum 22
		udplite checksum != 33-45
		udplite checksum { 33, 55, 67, 88 }
		udplite checksum { 33-55 }

*/
