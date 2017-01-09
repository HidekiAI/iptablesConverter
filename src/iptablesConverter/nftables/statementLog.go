package nftables

// statement is the action performed when the packet match the rule. It could be terminal and non-terminal. In a certain rule we can consider several non-terminal statements but only a single terminal statement.
// See: https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
log statement
level [over] <value> <unit> [burst <value> <unit>]	Log level
		log
		log level emerg
		log level alert
		log level crit
		log level err
		log level warn
		log level notice
		log level info
		log level debug
group <value> [queue-threshold <value>] [snaplen <value>] [prefix "<prefix>"]
		log prefix aaaaa-aaaaaa group 2 snaplen 33
		log group 2 queue-threshold 2
		log group 2 snaplen 33
*/
