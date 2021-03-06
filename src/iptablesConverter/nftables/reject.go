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
   REJECT STATEMENT
       reject with {icmp | icmp6 | icmpx} type {icmp_type | icmp6_type | icmpx_type}
       reject with {tcp} {reset}

       A reject statement is used to send back an error packet in response to the matched packet otherwise it is equivalent to drop so it is a terminating statement, ending rule traversal. This statement is only valid in the input,
       forward and output chains, and user-defined chains which are only called from those chains.

       reject statement type (ip)

       ┌──────────┬───────────────────────────────────────────┬────────────────────────────────────────────────────────────┐
       │Value     │ Description                               │ Type                                                       │
       ├──────────┼───────────────────────────────────────────┼────────────────────────────────────────────────────────────┤
       │icmp_type │ ICMP type response to be sent to the host │ net-unreachable, host-unreachable, prot-unreachable, port- │
       │          │                                           │ unreachable [default], net-prohibited, host-prohibited,    │
       │          │                                           │ admin-prohibited                                           │
       └──────────┴───────────────────────────────────────────┴────────────────────────────────────────────────────────────┘
       reject statement type (ip6)

       ┌───────────┬─────────────────────────────────────────────┬────────────────────────────────────────────────────────┐
       │Value      │ Description                                 │ Type                                                   │
       ├───────────┼─────────────────────────────────────────────┼────────────────────────────────────────────────────────┤
       │icmp6_type │ ICMPv6 type response to be sent to the host │ no-route, admin-prohibited, addr-unreachable, port-un‐ │
       │           │                                             │ reachable [default], policy-fail, reject-route         │
       └───────────┴─────────────────────────────────────────────┴────────────────────────────────────────────────────────┘
       reject statement type (inet)

       ┌───────────┬────────────────────────────────────────────────────────────┬─────────────────────────────────────────────────────────┐
       │Value      │ Description                                                │ Type                                                    │
       ├───────────┼────────────────────────────────────────────────────────────┼─────────────────────────────────────────────────────────┤
       │icmpx_type │ ICMPvXtype abstraction response to be sent to the host,    │ port-unreachable [default], admin-prohibited, no-route, │
       │           │ this is a set of types that overlap in IPv4 and IPv6 to be │ host-unreachable                                        │
       │           │ used from the inet family.                                 │                                                         │
       └───────────┴────────────────────────────────────────────────────────────┴─────────────────────────────────────────────────────────┘

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
type TStatementReject struct {
	Expr TChainedExpressions

	//EQ      *TEquate
	//Verdict *TStatementVerdict
	//Counter *TStatementCounter
}

func (expr *TStatementReject) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TStatementReject) GetTokens() []TToken {
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

func (rule *TTextStatement) parseStatementReject(iTokenIndexRO uint16) (*TStatementReject, error) {
	var retExpr TStatementReject
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenStatementReject {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'reject' (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
