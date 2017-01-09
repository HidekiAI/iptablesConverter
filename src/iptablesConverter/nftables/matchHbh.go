package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Hbh
hbh match
	nexthdr <proto>	Next protocol header
		hbh nexthdr { udplite, comp, udp, ah, sctp, esp, dccp, tcp, icmpv6}
		hbh nexthdr 22
		hbh nexthdr != 33-45
	hdrlength <length>	Header Length
		hbh hdrlength 22
		hbh hdrlength != 33-45
		hbh hdrlength { 33, 55, 67, 88 }

*/
