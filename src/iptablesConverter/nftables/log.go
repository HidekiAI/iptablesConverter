package nftables

import (
	"fmt"
	"log"
	"path/filepath"
	"runtime"
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
LOG STATEMENT
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
const (
	CTokenLogLevel             TToken = "level"
	CTokenLogSyslogLevel       TToken = "syslog-level"
	CTokenLogPrefix            TToken = "prefix"
	CTokenLogGroup             TToken = "group"
	CTokenLogSnaplen           TToken = "snaplen"
	CTokenLogQueueThreshold    TToken = "queue-threshold"
	CTokenLogLevelOver         TToken = "over"
	CTokenLogLevelBurst        TToken = "burst"
	CTokenLogFlags             TToken = "flags"
	CTokenLogFlagTcp           TToken = "tcp"
	CTokenLogFlagSequence      TToken = "sequence"
	CTokenLogFlagOptions       TToken = "options"
	CTokenLogFlagSkuid         TToken = "skuid"
	CTokenLogFlagEther         TToken = "ether"
	CTokenLogFlagAll           TToken = "all"
	CTokenLogLevelSyslogEmerg  TToken = "emerg"
	CTokenLogLevelSyslogAlert  TToken = "alert"
	CTokenLogLevelSyslogCrit   TToken = "crit"
	CTokenLogLevelSyslogErr    TToken = "err"
	CTokenLogLevelSyslogWarn   TToken = "warn"
	CTokenLogLevelSyslogNotice TToken = "notice"
	CTokenLogLevelSyslogInfo   TToken = "info"
	CTokenLogLevelSyslogDebug  TToken = "debug"
)

type TlogPrefix TToken
type TlogGroup uint16
type TlogSnaplen uint32
type TlogQThreshold uint32
type TLogFlag []TToken
type TStatementLog struct {
	Expr TChainedExpressions

	//Prefix         *TPrefix   // quoted string: Log message prefix
	//Level          *TToken   // string: emerge, alert, crit, err, warn [default], notice, info, debug
	//Group          *TGroup   // NFLOG group to send messages to
	//Snaplen        *TSnaplen   // Length of packet payload to include in netlink message
	//QueueThreshold *TQThreshold   // Number of packets to queue inside the kernel before sending them to userspace
	//Flag           *[]TToken // 'tcp', 'sequence', 'options', 'skuid', 'ether', 'all'
	//EQ             *TEquate
	//Verdict        *TStatementVerdict
	//Counter        *TStatementCounter
}

func (expr *TStatementLog) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TStatementLog) GetTokens() []TToken {
	var ret []TToken
	if expr.HasExpression() {
		for _, e := range expr.Expr.Expressions {
			switch tExpr := e.(type) {
			default:
				switch tE := e.(type) {
				case TStatementVerdict:
					ret = append(ret, GetTokens(tE)...)
				case TStatementLog:
					ret = append(ret, GetTokens(tE)...)
				case TStatementCounter:
					ret = append(ret, GetTokens(tE)...)
				case TEquate:
					ret = append(ret, GetTokens(tE)...)
				default:
					caller := ""
					// Caller(1) means the callee of this method (skip 1 stack)
					if _, f, ln, ok := runtime.Caller(1); ok {
						_, fn := filepath.Split(f)
						caller = fmt.Sprintf("%s:%d", fn, ln)
					}
					log.Panicf("%s: Unhandled type '%T' encountered (contents: '%+v')", caller, tE, tE)
				}
			}
		}
	}
	return ret
}

func (rule *TTextStatement) parseStatementLog(iTokenIndexRO uint16) (*TStatementLog, error) {
	var retExpr TStatementLog
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}

	//# log the UID which generated the packet and ip options
	//	ip filter output log flags skuid flags ip options
	//# log the tcp sequence numbers and tcp options from the TCP packet
	//	ip filter output log flags tcp sequence,options
	//# enable all supported log flags
	//	ip6 filter output log flags all
	//
	//#log [prefix quoted_string] [level syslog-level] [flags log-flags]
	//level [over] <value> <unit> [burst <value> <unit>]	Log level
	//		log
	//		log level emerg
	//		log level alert
	//		log level crit
	//		log level err
	//		log level warn
	//		log level notice
	//		log level info
	//		log level debug
	//#	log group nflog_group [prefix quoted_string] [queue-threshold value] [snaplen size]
	//group <value> [queue-threshold <value>] [snaplen <value>] [prefix "<prefix>"]
	//		log prefix aaaaa-aaaaaa group 2 snaplen 33
	//		log group 2 queue-threshold 2
	//		log group 2 snaplen 33
	// standalone:
	//  counter log drop #'log' and 'drop' are a separate statement in which, it collects counter, logs it, then drops the payload
	if tokens[0] == CTokenStatementLog {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	case CTokenLogLevel:
		{
			log.Panicf("Unhandled token '%v' for 'ah' (authentication header) (in %+v)", tokens, rule)
		}

	case CTokenLogGroup:
		{
			log.Panicf("Unhandled token '%v' for 'ah' (authentication header) (in %+v)", tokens, rule)
		}

	case CTokenLogPrefix:
		{
			log.Panicf("Unhandled token '%v' for 'ah' (authentication header) (in %+v)", tokens, rule)
		}

	case CTokenLogQueueThreshold:
		{
			log.Panicf("Unhandled token '%v' for 'ah' (authentication header) (in %+v)", tokens, rule)
		}

	case CTokenLogSnaplen:
		{
			log.Panicf("Unhandled token '%v' for 'ah' (authentication header) (in %+v)", tokens, rule)
		}

	default:
		{
			// Note: 'log' without any parameter is allowed
		}
	}

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
