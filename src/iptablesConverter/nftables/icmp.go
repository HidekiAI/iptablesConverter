package nftables

import (
	"fmt"
	"log"
	"path/filepath"
	"runtime"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Icmp
icmp match
	type <type>	ICMP packet type
		icmp type {echo-reply, destination-unreachable, source-quench, redirect, echo-request, time-exceeded, parameter-problem, timestamp-request, timestamp-reply, info-request, info-reply, address-mask-request, address-mask-reply, router-advertisement, router-solicitation}
	code	ICMP packet code
		icmp code 111
		icmp code != 33-55
		icmp code { 2, 4, 54, 33, 56}
	checksum <value>	ICMP packet checksum
		icmp checksum 12343
		icmp checksum != 11-343
		icmp checksum { 1111, 222, 343 }
	id <value>	ICMP packet id
		icmp id 12343
		icmp id != 11-343
		icmp id { 1111, 222, 343 }
	sequence <value>	ICMP packet sequence
		icmp sequence 12343
		icmp sequence != 11-343
		icmp sequence { 1111, 222, 343 }
	mtu <value>	ICMP packet mtu
		icmp mtu 12343
		icmp mtu != 11-343
		icmp mtu { 1111, 222, 343 }
	gateway <value>	ICMP packet gateway
		icmp gateway 12343
		icmp gateway != 11-343
		icmp gateway { 1111, 222, 343 }

*/
type TICMP struct {
	Expr TChainedExpressions

	//EQ      *TEquate
	//Verdict *TStatementVerdict
	//Counter *TStatementCounter
}

func (expr *TICMP) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TICMP) GetTokens() []TToken {
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

func (rule *TTextStatement) parsePayloadIcmp(iTokenIndexRO uint16) (*TICMP, error) {
	var retExpr TICMP
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchICMP {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'icmp' (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
