package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Frag
frag match
	nexthdr <proto>	Next protocol header
		frag nexthdr { udplite, comp, udp, ah, sctp, esp, dccp, tcp, ipv6-icmp, icmp}
		frag nexthdr 6
		frag nexthdr != 50-51
	reserved <value>
		frag reserved 22
		frag reserved != 33-45
		frag reserved { 33, 55, 67, 88}
	frag-off <value>
		frag frag-off 22
		frag frag-off != 33-45
		frag frag-off { 33, 55, 67, 88}
	more-fragments <value>
		frag more-fragments 0
		frag more-fragments 0
	id <value>
		frag id 1
		frag id 33-45

*/
