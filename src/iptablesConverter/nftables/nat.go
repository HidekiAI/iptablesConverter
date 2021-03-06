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
   NAT STATEMENTS
       snat to address [:port] [persistent, random, fully-random]
       snat to address - address [:port - port] [persistent, random, fully-random]
       dnat to address [:port] [persistent, random, fully-random]
       dnat to address [:port - port] [persistent, random, fully-random]

       The nat statements are only valid from nat chain types.

       The snat statement is only valid in the postrouting and input hooks, it specifies that the source address of the packet should be modified. The dnat statement is only valid in the prerouting and output chains, it specifies that
       the destination address of the packet should be modified. You can use non-base chains which are called from base chains of nat chain type too. All future packets in this connection will also be mangled, and rules should cease
       being examined.

       NAT statement values

       ┌───────────┬────────────────────────────────────────────────────────────┬────────────────────────────────────────────────────────┐
       │Expression │ Description                                                │ Type                                                   │
       ├───────────┼────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────┤
       │address    │ Specifies that the source/destination address of the pack‐ │ ipv4_addr, ipv6_addr, eg. abcd::1234, or you can use a │
       │           │ et should be modified. You may specify a mapping to relate │ mapping, eg. meta mark map { 10 : 192.168.1.2, 20 :    │
       │           │ a list of tuples composed of arbitrary expression key with │ 192.168.1.3 }                                          │
       │           │ address value.                                             │                                                        │
       ├───────────┼────────────────────────────────────────────────────────────┼────────────────────────────────────────────────────────┤
       │port       │ Specifies that the source/destination address of the pack‐ │ port number (16 bits)                                  │
       │           │ et should be modified.                                     │                                                        │
       └───────────┴────────────────────────────────────────────────────────────┴────────────────────────────────────────────────────────┘
       NAT statement flags

       ┌─────────────┬──────────────────────────────────────────────────────────────────────────────┐
       │Flag         │ Description                                                                  │
       ├─────────────┼──────────────────────────────────────────────────────────────────────────────┤
       │persistent   │ Gives a client the same source-/destination-address for each connection.     │
       ├─────────────┼──────────────────────────────────────────────────────────────────────────────┤
       │random       │ If used then port mapping will be randomized using a random seeded MD5 hash  │
       │             │ mix using source and destination address and destination port.               │
       ├─────────────┼──────────────────────────────────────────────────────────────────────────────┤
       │fully-random │ If used then port mapping is generated based on a 32-bit pseudo-random algo‐ │
       │             │ rithm.                                                                       │
       └─────────────┴──────────────────────────────────────────────────────────────────────────────┘

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
type TStatementNat struct {
	Expr TChainedExpressions

	//EQ      *TEquate
	//Verdict *TStatementVerdict
	//Counter *TStatementCounter
}

func (expr *TStatementNat) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TStatementNat) GetTokens() []TToken {
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

func (rule *TTextStatement) parseStatementNat(iTokenIndexRO uint16) (*TStatementNat, error) {
	var retExpr TStatementNat
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenStatementSNAT {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	} else if tokens[0] == CTokenStatementDNAT {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for nat ('dnat', 'snat', or 'masquerade') (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
