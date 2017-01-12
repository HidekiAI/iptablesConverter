package nftables

import (
	"log"
)

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
G STATEMENT
       log [prefix quoted_string] [level syslog-level] [flags log-flags]
       log group nflog_group [prefix quoted_string] [queue-threshold value] [snaplen size]

       The log statement enables logging of matching packets. When this statement is used from a rule, the Linux kernel will print some information on all matching packets, such as header fields, via the kernel log (where it can be
       read with dmesg(1) or read in the syslog). If the group number is specified, the Linux kernel will pass the packet to nfnetlink_log which will multicast the packet through a netlink socket to the specified multicast group. One
       or more userspace processes may subscribe to the group to receive the packets, see libnetfilter_queue documentation for details. This is a non-terminating statement, so the rule evaluation continues after the packet is logged.

       log statement options

       ┌────────────────┬───────────────────────────────────────────────────────────┬──────────────────────────────────────────────────────────┐
       │Keyword         │ Description                                               │ Type                                                     │
       ├────────────────┼───────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
       │prefix          │ Log message prefix                                        │ quoted string                                            │
       ├────────────────┼───────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
       │syslog-level    │ Syslog level of logging                                   │ string: emerg, alert, crit, err, warn [default], notice, │
       │                │                                                           │ info, debug                                              │
       ├────────────────┼───────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
       │group           │ NFLOG group to send messages to                           │ unsigned integer (16 bit)                                │
       ├────────────────┼───────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
       │snaplen         │ Length of packet payload to include in netlink message    │ unsigned integer (32 bit)                                │
       ├────────────────┼───────────────────────────────────────────────────────────┼──────────────────────────────────────────────────────────┤
       │queue-threshold │ Number of packets to queue inside the kernel before send‐ │ unsigned integer (32 bit)                                │
       │                │ ing them to userspace                                     │                                                          │
       └────────────────┴───────────────────────────────────────────────────────────┴──────────────────────────────────────────────────────────┘
       log-flags

       ┌─────────────┬───────────────────────────────────────────────────────────┐
       │Flag         │ Description                                               │
       ├─────────────┼───────────────────────────────────────────────────────────┤
       │tcp sequence │ Log TCP sequence numbers.                                 │
       ├─────────────┼───────────────────────────────────────────────────────────┤
       │tcp options  │ Log options from the TCP packet header.                   │
       ├─────────────┼───────────────────────────────────────────────────────────┤
       │ip options   │ Log options from the IP/IPv6 packet header.               │
       ├─────────────┼───────────────────────────────────────────────────────────┤
       │skuid        │ Log the userid of the process which generated the packet. │
       ├─────────────┼───────────────────────────────────────────────────────────┤
       │ether        │ Decode MAC addresses and protocol.                        │
       ├─────────────┼───────────────────────────────────────────────────────────┤
       │all          │ Enable all log flags listed above.                        │
       └─────────────┴───────────────────────────────────────────────────────────┘
       Using log statement

       # log the UID which generated the packet and ip options
       ip filter output log flags skuid flags ip options

       # log the tcp sequence numbers and tcp options from the TCP packet
       ip filter output log flags tcp sequence,options

       # enable all supported log flags
       ip6 filter output log flags all

*/
type TStatementLog struct {
	//EQ      TEquate
	//Verdict TStatementVerdict
	Tokens []TToken
}

func parseStatementLog(rule *TTextStatement) *TStatementLog {
	retLog := new(TStatementLog)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenStatementLog {
		retLog.Tokens = append(retLog.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'log' (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented: %+v", rule)
	return nil
}
