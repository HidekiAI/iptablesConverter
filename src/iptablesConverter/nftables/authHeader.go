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
Ah
ah match
	hdrlength <length>	AH header length
		ah hdrlength 11-23
		ah hdrlength != 11-23
		ah hdrlength {11, 23, 44 }
	reserved <value>
		ah reserved 22
		ah reserved != 33-45
		ah reserved {23, 100 }
		ah reserved { 33-55 }
	spi <value>
		ah spi 111
		ah spi != 111-222
		ah spi {111, 122 }
	sequence <sequence>	Sequence Number
		ah sequence 123
		ah sequence {23, 25, 33}
		ah sequence != 23-33

*/

// ah [AH header field]
type TahHdrLength uint8
type TahReserved uint8
type TahSpi uint32
type TahSequence uint32
type TExpressionHeaderAH struct { // authentication header
	Expr TChainedExpressions

	//Nexthdr   *Tinetservice // Next header protocol
	//Hdrlength *THdrLength        // AH Header length
	//Reserved  *TReserved        // Reserved area 4-bits
	//Spi       *TSpi       // Security Parameter Index
	//Sequence  *TSequence       // Sequence number
	//EQ        *TEquate
	//Verdict   *TStatementVerdict
	//Counter   *TStatementCounter
}

func (expr *TExpressionHeaderAH) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TExpressionHeaderAH) GetTokens() []TToken {
	var ret []TToken
	if expr.HasExpression() {
		for _, e := range expr.Expr.Expressions {
			switch tExpr := e.(type) {
			case TahHdrLength:
				ret = append(ret, GetTokens(tExpr)...)
			case TahReserved:
				ret = append(ret, GetTokens(tExpr)...)
			case TahSpi:
				ret = append(ret, GetTokens(tExpr)...)
			case TahSequence:
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

func (rule *TTextStatement) parsePayloadAh(iTokenIndexRO uint16) (*TExpressionHeaderAH, error) {
	var retExpr TExpressionHeaderAH
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchAH {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'ah' (authentication header) (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
