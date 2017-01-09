package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
ip6 match
	dscp <value>
		ip6 dscp cs1
		ip6 dscp != cs1
		ip6 dscp 0x38
		ip6 dscp != 0x20
		ip6 dscp {cs0, cs1, cs2, cs3, cs4, cs5, cs6, cs7, af11, af12, af13, af21, af22, af23, af31, af32, af33, af41, af42, af43, ef}
	flowlabel <label>	Flow label
		ip6 flowlabel 22
		ip6 flowlabel != 233
		ip6 flowlabel { 33, 55, 67, 88 }
		ip6 flowlabel { 33-55 }
	length <length>	Payload length
		ip6 length 232
		ip6 length != 233
		ip6 length 333-435
		ip6 length != 333-453
		ip6 length { 333, 553, 673, 838}
	nexthdr <header>	Next header type (Upper layer protocol number)
		ip6 nexthdr {esp, udp, ah, comp, udplite, tcp, dccp, sctp, icmpv6}
		ip6 nexthdr esp
		ip6 nexthdr != esp
		ip6 nexthdr { 33-44 }
		ip6 nexthdr 33-44
		ip6 nexthdr != 33-44
	hoplimit <hoplimit>	Hop limit
		ip6 hoplimit 1
		ip6 hoplimit != 233
		ip6 hoplimit 33-45
		ip6 hoplimit != 33-45
		ip6 hoplimit {33, 55, 67, 88}
		ip6 hoplimit {33-55}
	saddr <ip source address>	Source Address
		ip6 saddr 1234:1234:1234:1234:1234:1234:1234:1234
		ip6 saddr ::1234:1234:1234:1234:1234:1234:1234
		ip6 saddr ::/64
		ip6 saddr ::1 ip6 daddr ::2
	daddr <ip destination address>	Destination Address
		ip6 daddr 1234:1234:1234:1234:1234:1234:1234:1234
		ip6 daddr != ::1234:1234:1234:1234:1234:1234:1234-1234:1234::1234:1234:1234:1234:1234
	version <version>	IP header version
		ip6 version 6
*/
