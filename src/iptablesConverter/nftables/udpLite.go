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
Udplite
udplite match
	dport <destination port>	Destination port
		udplite dport 22
		udplite dport != 33-45
		udplite dport { 33-55 }
		udplite dport {telnet, http, https }
		udplite dport vmap { 22 : accept, 23 : drop }
		udplite dport vmap { 25:accept, 28:drop }
	sport < source port>	Source port
		udplite sport 22
		udplite sport != 33-45
		udplite sport { 33, 55, 67, 88}
		udplite sport { 33-55}
		udplite sport vmap { 25:accept, 28:drop }
		udplite sport 1024 tcp dport 22
	checksum <checksum>	Checksum
		udplite checksum 22
		udplite checksum != 33-45
		udplite checksum { 33, 55, 67, 88 }
		udplite checksum { 33-55 }

*/

// udplite [UDP-Lite header field]
type TudpliteSport Tinetservice
type TudpliteDport Tinetservice
type TudpliteCsCov uint16
type TudpliteChecksum uint16
type TExpressionHeaderUdpLite struct {
	Expr TChainedExpressions

	//Sport    *Tinetservice
	//Dport    *Tinetservice
	//Cscov    *uint16 // Checksum coverage
	//Checksum *uint16
	//EQ       *TEquate
	//Verdict  *TStatementVerdict
	//Counter  *TStatementCounter
}

func (expr *TExpressionHeaderUdpLite) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TExpressionHeaderUdpLite) GetTokens() []TToken {
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

func (rule *TTextStatement) parsePayloadUdpLite(iTokenIndexRO uint16) (*TExpressionHeaderUdpLite, error) {
	var retExpr TExpressionHeaderUdpLite
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchUDPLite {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'udplite' (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
