package nftables

// statement is the action performed when the packet match the rule. It could be terminal and non-terminal. In a certain rule we can consider several non-terminal statements but only a single terminal statement.
// See: https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
nat statement
	dnat <destination address>	Destination address translation
		dnat 192.168.3.2
		dnat ct mark map { 0x00000014 : 1.2.3.4}
	snat <ip source address>	Source address translation
		snat 192.168.3.2
		snat 2001:838:35f:1::-2001:838:35f:2:::100
	masquerade [<type>] [to :<port>]	Masquerade
		masquerade
		masquerade persistent,fully-random,random
		masquerade to :1024
		masquerade to :1024-2048
*/
