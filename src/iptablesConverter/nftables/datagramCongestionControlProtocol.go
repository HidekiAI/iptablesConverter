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
Dccp
dccp match
	dport <destination port>	Destination port
		dccp dport 22
		dccp dport != 33-45
		dccp dport { 33-55 }
		dccp dport {telnet, http, https }
		dccp dport vmap { 22 : accept, 23 : drop }
		dccp dport vmap { 25:accept, 28:drop }
	sport < source port>	Source port
		dccp sport 22
		dccp sport != 33-45
		dccp sport { 33, 55, 67, 88}
		dccp sport { 33-55}
		dccp sport vmap { 25:accept, 28:drop }
		dccp sport 1024 tcp dport 22
	type <type>	Type of packet
		dccp type {request, response, data, ack, dataack, closereq, close, reset, sync, syncack}
		dccp type request
		dccp type != request

*/
// dccp [DCCP header field]
type TdccpSPort Tinetservice
type TdccpDPort Tinetservice
type TExpressionHeaderDccp struct {
	Expr TChainedExpressions

	//Sport   *Tinetservice
	//Dport   *Tinetservice
	//EQ      *TEquate
	//Verdict *TStatementVerdict
	//Counter *TStatementCounter
}

func (expr *TExpressionHeaderDccp) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TExpressionHeaderDccp) GetTokens() []TToken {
	var ret []TToken
	if expr.HasExpression() {
		for _, e := range expr.Expr.Expressions {
			switch tExpr := e.(type) {
			case TdccpSPort:
				ret = append(ret, GetTokens(tExpr)...)
			case TdccpDPort:
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

func (rule *TTextStatement) parsePayloadDccp(iTokenIndexRO uint16) (*TExpressionHeaderDccp, error) {
	var retExpr TExpressionHeaderDccp
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchDCCP {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'dccp' (datagram congestion control protocol) (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
