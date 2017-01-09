package nftables

// statement is the action performed when the packet match the rule. It could be terminal and non-terminal. In a certain rule we can consider several non-terminal statements but only a single terminal statement.
// See: https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
limit statement
	rate [over] <value> <unit> [burst <value> <unit>]	Rate limit
		limit rate 400/minute
		limit rate 400/hour
		limit rate over 40/day
		limit rate over 400/week
		limit rate over 1023/second burst 10 packets
		limit rate 1025 kbytes/second
		limit rate 1023000 mbytes/second
		limit rate 1025 bytes/second burst 512 bytes
		limit rate 1025 kbytes/second burst 1023 kbytes
		limit rate 1025 mbytes/second burst 1025 kbytes
		limit rate 1025000 mbytes/second burst 1023 mbytes
*/
