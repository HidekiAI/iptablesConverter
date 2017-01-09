package nftables

// statement is the action performed when the packet match the rule. It could be terminal and non-terminal. In a certain rule we can consider several non-terminal statements but only a single terminal statement.
// See: https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
reject statement
	with <protocol> type <type>
		reject
		reject with icmp type host-unreachable
		reject with icmp type net-unreachable
		reject with icmp type prot-unreachable
		reject with icmp type port-unreachable
		reject with icmp type net-prohibited
		reject with icmp type host-prohibited
		reject with icmp type admin-prohibited
		reject with icmpv6 type no-route
		reject with icmpv6 type admin-prohibited
		reject with icmpv6 type addr-unreachable
		reject with icmpv6 type port-unreachable
		ip protocol tcp reject with tcp reset
		reject with icmpx type host-unreachable
		reject with icmpx type no-route
		reject with icmpx type admin-prohibited
		reject with icmpx type port-unreachable

*/
