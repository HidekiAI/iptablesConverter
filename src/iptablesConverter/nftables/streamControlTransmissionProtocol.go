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
Sctp
sctp match
	dport <destination port>	Destination port
		sctp dport 22
		sctp dport != 33-45
		sctp dport { 33-55 }
		sctp dport {telnet, http, https }
		sctp dport vmap { 22 : accept, 23 : drop }
		sctp dport vmap { 25:accept, 28:drop }
	sport < source port>	Source port
		sctp sport 22
		sctp sport != 33-45
		sctp sport { 33, 55, 67, 88}
		sctp sport { 33-55}
		sctp sport vmap { 25:accept, 28:drop }
		sctp sport 1024 tcp dport 22
	checksum <checksum>	Checksum
		sctp checksum 22
		sctp checksum != 33-45
		sctp checksum { 33, 55, 67, 88 }
		sctp checksum { 33-55 }
	vtag <tag>	Verification tag
		sctp vtag 22
		sctp vtag != 33-45
		sctp vtag { 33, 55, 67, 88 }
		sctp vtag { 33-55 }

*/

// sctp [SCTP header field]
type TsctpVTag uint32
type TsctpChecksum uint32
type TsctpSPort Tinetservice
type TsctpDPort Tinetservice
type TExpressionHeaderSctp struct {
	Expr TChainedExpressions

	//Sport    *Tinetservice
	//Dport    *Tinetservice
	//Vtag     *TVTag // Verification tag
	//Checksum *TChecksum
	//EQ       *TEquate
	//Verdict  *TStatementVerdict
	//Counter  *TStatementCounter
}

func (expr *TExpressionHeaderSctp) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TExpressionHeaderSctp) GetTokens() []TToken {
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

func (rule *TTextStatement) parsePayloadSctp(iTokenIndexRO uint16) (*TExpressionHeaderSctp, error) {
	var retExpr TExpressionHeaderSctp
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchSCTP {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'sctp' (stream control transmission protocol) (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
