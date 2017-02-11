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
Comp
comp match
	nexthdr <protocol>	Next header protocol (Upper layer protocol)
		comp nexthdr != esp
		comp nexthdr {esp, ah, comp, udp, udplite, tcp, tcp, dccp, sctp}
	flags <flags>	Flags
		comp flags 0x0
		comp flags != 0x33-0x45
		comp flags {0x33, 0x55, 0x67, 0x88}
	cpi <value>	Compression Parameter Index
		comp cpi 22
		comp cpi != 33-45
		comp cpi {33, 55, 67, 88}

*/

type Tbitmask uint

// comp [IPComp header field]
type TipcompNextHdr Tinetservice
type TipcompFlags Tbitmask
type TipcompCpi uint16
type TExpressionHeaderIpcomp struct {
	Expr TChainedExpressions

	//Nexthdr *Tinetservice // Next header protocol
	//Flags   *Tbitmask
	//Cpi     *uint16 // Compression Parameter Index
	//EQ      *TEquate
	//Verdict *TStatementVerdict
	//Counter *TStatementCounter
}

func (expr *TExpressionHeaderIpcomp) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TExpressionHeaderIpcomp) GetTokens() []TToken {
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

func (rule *TTextStatement) parsePayloadIpComp(iTokenIndexRO uint16) (*TExpressionHeaderIpcomp, error) {
	var retExpr TExpressionHeaderIpcomp
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchComp {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'comp' (ip compression) (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
