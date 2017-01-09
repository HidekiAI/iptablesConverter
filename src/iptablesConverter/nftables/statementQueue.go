package nftables

// statement is the action performed when the packet match the rule. It could be terminal and non-terminal. In a certain rule we can consider several non-terminal statements but only a single terminal statement.
// See: https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
queue statement
	num <value> <scheduler>
		queue
		queue num 2
		queue num 2-3
		queue num 4-5 fanout bypass
		queue num 4-5 fanout
		queue num 4-5 bypass
*/
