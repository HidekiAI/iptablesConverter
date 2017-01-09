package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Rt
rt match
	nexthdr <proto>	Next protocol header
		rt nexthdr { udplite, ipcomp, udp, ah, sctp, esp, dccp, tcp, ipv6-icmp }
		rt nexthdr 22
		rt nexthdr != 33-45
	hdrlength <length>	Header Length
		rt hdrlength 22
		rt hdrlength != 33-45
		rt hdrlength { 33, 55, 67, 88 }
	type <type>
		rt type 22
		rt type != 33-45
		rt type { 33, 55, 67, 88 }
	seg-left <value>
		rt seg-left 22
		rt seg-left != 33-45
		rt seg-left { 33, 55, 67, 88}

*/
