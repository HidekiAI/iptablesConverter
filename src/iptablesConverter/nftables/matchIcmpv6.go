package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Icmpv6
icmpv6 match
	type <type>	ICMPv6 packet type
		icmpv6 type {destination-unreachable, packet-too-big, time-exceeded, echo-request, echo-reply, mld-listener-query, mld-listener-report, mld-listener-reduction, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect, parameter-problem, router-renumbering}
	code <code>	ICMPv6 packet code
		icmpv6 code 4
		icmpv6 code 3-66
		icmpv6 code {5, 6, 7}
	checksum <value>	ICMPv6 packet checksum
		icmpv6 checksum 12343
		icmpv6 checksum != 11-343
		icmpv6 checksum { 1111, 222, 343 }
	id <value>	ICMPv6 packet id
		icmpv6 id 12343
		icmpv6 id != 11-343
		icmpv6 id { 1111, 222, 343 }
	sequence <value>	ICMPv6 packet sequence
		icmpv6 sequence 12343
		icmpv6 sequence != 11-343
		icmpv6 sequence { 1111, 222, 343 }
	mtu <value>	ICMPv6 packet mtu
		icmpv6 mtu 12343
		icmpv6 mtu != 11-343
		icmpv6 mtu { 1111, 222, 343 }
	max-delay <value>	ICMPv6 packet max delay
		icmpv6 max-delay 33-45
		icmpv6 max-delay != 33-45
		icmpv6 max-delay {33, 55, 67, 88}

*/