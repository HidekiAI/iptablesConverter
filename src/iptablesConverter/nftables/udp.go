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
Udp
udp match
	dport <destination port>	Destination port
		udp dport 22
		udp dport != 33-45
		udp dport { 33-55 }
		udp dport {telnet, http, https }
		udp dport vmap { 22 : accept, 23 : drop }
		udp dport vmap { 25:accept, 28:drop }
	sport < source port>	Source port
		udp sport 22
		udp sport != 33-45
		udp sport { 33, 55, 67, 88}
		udp sport { 33-55}
		udp sport vmap { 25:accept, 28:drop }
		udp sport 1024 tcp dport 22
	length <length>	Total packet length
		udp length 6666
		udp length != 50-65
		udp length { 50, 65 }
		udp length { 35-50 }
	checksum <checksum>	UDP checksum
		udp checksum 22
		udp checksum != 33-45
		udp checksum { 33, 55, 67, 88 }
		udp checksum { 33-55 }

*/

// udp [UDP header field]
type TudpSport Tinetservice
type TudpDport Tinetservice
type TudpLength uint16
type TudpChecksum uint16
type TExpressionHeaderUdp struct {
	Expr TChainedExpressions

	//Sport    *Tinetservice
	//Dport    *Tinetservice
	//Length   *uint16
	//Checksum *uint16
	//EQ       *TEquate
	//Verdict  *TStatementVerdict
	//Counter  *TStatementCounter
}

func (expr *TExpressionHeaderUdp) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TExpressionHeaderUdp) GetTokens() []TToken {
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

func (rule *TTextStatement) parsePayloadUdp(iTokenIndexRO uint16) (*TExpressionHeaderUdp, error) {
	var retExpr TExpressionHeaderUdp
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchUDP {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'udp' (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
