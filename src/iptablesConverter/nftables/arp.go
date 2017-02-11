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
Arp
arp match
	ptype <value>	Payload type
		arp ptype 0x0800
	htype <value>	Header type
		arp htype 1
		arp htype != 33-45
		arp htype { 33, 55, 67, 88}
	hlen <length>	Header Length
		arp hlen 1
		arp hlen != 33-45
		arp hlen { 33, 55, 67, 88}
	plen <length>	Payload length
		arp plen 1
		arp plen != 33-45
		arp plen { 33, 55, 67, 88}
	operation <value>
		arp operation {nak, inreply, inrequest, rreply, rrequest, reply, request}

*/
// arp [ARP header field]
type Tarpop TToken
type TarpHtype uint16
type TarpHLen uint8
type TarpPLen uint8
type TExpressionHeaderArp struct {
	Expr TChainedExpressions
	//Htype     *THtype // ARP hardware type
	//Ptype     *Tethertype
	//Hlen      *THLen
	//Plen      *TPlen
	//Operation *Tarpop
	//EQ      *TEquate
	//Verdict *TStatementVerdict
	//Counter *TStatementCounter
}

func (expr *TExpressionHeaderArp) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TExpressionHeaderArp) GetTokens() []TToken {
	var ret []TToken
	if expr.HasExpression() {
		for _, e := range expr.Expr.Expressions {
			switch tExpr := e.(type) {
			case Tarpop:
				ret = append(ret, GetTokens(tExpr)...)
			case TarpHtype:
				ret = append(ret, GetTokens(tExpr)...)
			case TarpHLen:
				ret = append(ret, GetTokens(tExpr)...)
			case TarpPLen:
				ret = append(ret, GetTokens(tExpr)...)
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

func (rule *TTextStatement) parsePayloadArp(iTokenIndexRO uint16) (*TExpressionHeaderArp, error) {
	var retExpr TExpressionHeaderArp
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchARP {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'arp' (in %+v)", tokens, rule)
		}
	}
	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
