package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Ct
ct match
	state <state>	State of the connection
		ct state { new, established, related, untracked }
		ct state != related
		ct state established
		ct state 8
	direction <value>	Direction of the packet relative to the connection
		ct direction original
		ct direction != original
		ct direction {reply, original}
	status <status>	Status of the connection
		ct status expected
		ct status != expected
		ct status {expected,seen-reply,assured,confirmed,snat,dnat,dying}
	mark [set]	Mark of the connection
		ct mark 0
		ct mark or 0x23 == 0x11
		ct mark or 0x3 != 0x1
		ct mark and 0x23 == 0x11
		ct mark and 0x3 != 0x1
		ct mark xor 0x23 == 0x11
		ct mark xor 0x3 != 0x1
		ct mark 0x00000032
		ct mark != 0x00000032
		ct mark 0x00000032-0x00000045
		ct mark != 0x00000032-0x00000045
		ct mark {0x32, 0x2222, 0x42de3}
		ct mark {0x32-0x2222, 0x4444-0x42de3}
		ct mark set 0x11 xor 0x1331
		ct mark set 0x11333 and 0x11
		ct mark set 0x12 or 0x11
		ct mark set 0x11
		ct mark set mark
		ct mark set mark map { 1 : 10, 2 : 20, 3 : 30 }
	expiration	Connection expiration time
		ct expiration 30
		ct expiration 30s
		ct expiration != 233
		ct expiration != 3m53s
		ct expiration 33-45
		ct expiration 33s-45s
		ct expiration != 33-45
		ct expiration != 33s-45s
		ct expiration {33, 55, 67, 88}
		ct expiration { 1m7s, 33s, 55s, 1m28s}
	helper "<helper>"	Helper associated with the connection
		ct helper "ftp"
	[original | reply] bytes <value>
		ct original bytes > 100000
		ct bytes > 100000
	[original | reply] packets <value>
		ct reply packets < 100
	[original | reply] saddr <ip source address>
		ct original saddr 192.168.0.1
		ct reply saddr 192.168.0.1
		ct original saddr 192.168.1.0/24
		ct reply saddr 192.168.1.0/24
	[original | reply] daddr <ip destination address>
		ct original daddr 192.168.0.1
		ct reply daddr 192.168.0.1
		ct original daddr 192.168.1.0/24
		ct reply daddr 192.168.1.0/24
	[original | reply] l3proto <protocol>
		ct original l3proto ipv4
	[original | reply] protocol <protocol>
		ct original protocol 6
	[original | reply] proto-dst <port>
		ct original proto-dst 22
	[original | reply] proto-src <port>
		ct reply proto-src 53

*/
