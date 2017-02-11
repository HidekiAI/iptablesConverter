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
Mh
mh match
	nexthdr <proto>	Next protocol header
		mh nexthdr { udplite, ipcomp, udp, ah, sctp, esp, dccp, tcp, ipv6-icmp }
		mh nexthdr 22
		mh nexthdr != 33-45
	hdrlength <length>	Header Length
		mh hdrlength 22
		mh hdrlength != 33-45
		mh hdrlength { 33, 55, 67, 88 }
	type <type>
		mh type {binding-refresh-request, home-test-init, careof-test-init, home-test, careof-test, binding-update, binding-acknowledgement, binding-error, fast-binding-update, fast-binding-acknowledgement, fast-binding-advertisement, experimental-mobility-header, home-agent-switch-message}
		mh type home-agent-switch-message
		mh type != home-agent-switch-message
	reserved <value>
		mh reserved 22
		mh reserved != 33-45
		mh reserved { 33, 55, 67, 88}
	checksum <value>
		mh checksum 22
		mh checksum != 33-45
		mh checksum { 33, 55, 67, 88}

*/
type TMH struct {
	Expr TChainedExpressions

	//EQ      *TEquate
	//Verdict *TStatementVerdict
	//Counter *TStatementCounter
}

func (expr *TMH) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TMH) GetTokens() []TToken {
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

func (rule *TTextStatement) parsePayloadMh(iTokenIndexRO uint16) (*TMH, error) {
	var retExpr TMH
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchMH {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'mh' (mobility header) (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
