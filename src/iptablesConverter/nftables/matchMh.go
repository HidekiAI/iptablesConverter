package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Mh
mh match
	nexthdr <proto>	Next protocol header
		mh nexthdr { udplite, ipcomp, udp, ah, sctp, esp, dccp, tcp, ipv6-icmp }
		mh nexthdr 22
		mh nexthdr != 33-45
	hdrlength <length>	Header Length
		mh hdrlength 22
		mh hdrlength != 33-45
		mh hdrlength { 33, 55, 67, 88 }
	type <type>
		mh type {binding-refresh-request, home-test-init, careof-test-init, home-test, careof-test, binding-update, binding-acknowledgement, binding-error, fast-binding-update, fast-binding-acknowledgement, fast-binding-advertisement, experimental-mobility-header, home-agent-switch-message}
		mh type home-agent-switch-message
		mh type != home-agent-switch-message
	reserved <value>
		mh reserved 22
		mh reserved != 33-45
		mh reserved { 33, 55, 67, 88}
	checksum <value>
		mh checksum 22
		mh checksum != 33-45
		mh checksum { 33, 55, 67, 88}

*/
