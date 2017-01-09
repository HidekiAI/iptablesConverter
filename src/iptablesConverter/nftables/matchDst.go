package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Dst
dst match
	nexthdr <proto>	Next protocol header
		dst nexthdr { udplite, ipcomp, udp, ah, sctp, esp, dccp, tcp, ipv6-icmp}
		dst nexthdr 22
		dst nexthdr != 33-45
	hdrlength <length>	Header Length
		dst hdrlength 22
		dst hdrlength != 33-45
		dst hdrlength { 33, 55, 67, 88 }

*/
