package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Meta: meta matches packet by metainformation.
meta match
	iifname <input interface name>	Input interface name
		meta iifname "eth0"
		meta iifname != "eth0"
		meta iifname {"eth0", "lo"}
		meta iifname "eth*"
	oifname <output interface name>	Output interface name
		meta oifname "eth0"
		meta oifname != "eth0"
		meta oifname {"eth0", "lo"}
		meta oifname "eth*"
	iif <input interface index>	Input interface index
		meta iif eth0
		meta iif != eth0
	oif <output interface index>	Output interface index
		meta oif lo
		meta oif != lo
		meta oif {eth0, lo}
	iiftype <input interface type>	Input interface type
		meta iiftype {ether, ppp, ipip, ipip6, loopback, sit, ipgre}
		meta iiftype != ether
		meta iiftype ether
	oiftype <output interface type>	Output interface hardware type
		meta oiftype {ether, ppp, ipip, ipip6, loopback, sit, ipgre}
		meta oiftype != ether
		meta oiftype ether
	length <length>	Length of the packet in bytes
		meta length 1000
		meta length != 1000
		meta length > 1000
		meta length 33-45
		meta length != 33-45
		meta length { 33, 55, 67, 88 }
		meta length { 33-55, 67-88 }
	protocol <protocol>	ethertype protocol
		meta protocol ip
		meta protocol != ip
		meta protocol { ip, arp, ip6, vlan }
	nfproto <protocol>
		meta nfproto ipv4
		meta nfproto != ipv6
		meta nfproto { ipv4, ipv6 }
	l4proto <protocol>
		meta l4proto 22
		meta l4proto != 233
		meta l4proto 33-45
		meta l4proto { 33, 55, 67, 88 }
		meta l4proto { 33-55 }
	mark [set] <mark>	Packet mark
		meta mark 0x4
		meta mark 0x00000032
		meta mark and 0x03 == 0x01
		meta mark and 0x03 != 0x01
		meta mark != 0x10
		meta mark or 0x03 == 0x01
		meta mark or 0x03 != 0x01
		meta mark xor 0x03 == 0x01
		meta mark xor 0x03 != 0x01
		meta mark set 0xffffffc8 xor 0x16
		meta mark set 0x16 and 0x16
		meta mark set 0xffffffe9 or 0x16
		meta mark set 0xffffffde and 0x16
		meta mark set 0x32 or 0xfffff
		meta mark set 0xfffe xor 0x16
	skuid <user id>	UID associated with originating socket
		meta skuid {bin, root, daemon}
		meta skuid root
		meta skuid != root
		meta skuid lt 3000
		meta skuid gt 3000
		meta skuid eq 3000
		meta skuid 3001-3005
		meta skuid != 2001-2005
		meta skuid { 2001-2005 }
	skgid <group id>	GID associated with originating socket
		meta skgid {bin, root, daemon}
		meta skgid root
		meta skgid != root
		meta skgid lt 3000
		meta skgid gt 3000
		meta skgid eq 3000
		meta skgid 3001-3005
		meta skgid != 2001-2005
		meta skgid { 2001-2005 }
	rtclassid <class>	Routing realm
		meta rtclassid cosmos
	pkttype <type>	Packet type
		meta pkttype broadcast
		meta pkttype != broadcast
		meta pkttype { broadcast, unicast, multicast}
	cpu <cpu index>	CPU ID
		meta cpu 1
		meta cpu != 1
		meta cpu 1-3
		meta cpu != 1-2
		meta cpu { 2,3 }
		meta cpu { 2-3, 5-7 }
	iifgroup <input group>	Input interface group
		meta iifgroup 0
		meta iifgroup != 0
		meta iifgroup default
		meta iifgroup != default
		meta iifgroup {default}
		meta iifgroup { 11,33 }
		meta iifgroup {11-33}
	oifgroup <group>	Output interface group
		meta oifgroup 0
		meta oifgroup != 0
		meta oifgroup default
		meta oifgroup != default
		meta oifgroup {default}
		meta oifgroup { 11,33 }
		meta oifgroup {11-33}
	cgroup <group>
		meta cgroup 1048577
		meta cgroup != 1048577
		meta cgroup { 1048577, 1048578 }
		meta cgroup 1048577-1048578
		meta cgroup != 1048577-1048578
		meta cgroup {1048577-1048578}

*/
