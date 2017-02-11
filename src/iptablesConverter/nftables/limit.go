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
   LIMIT STATEMENT
       limit rate [over] packet_number / {second | minute | hour | day} [burst packet_number packets]
       limit rate [over] byte_number {bytes | kbytes | mbytes} / {second | minute | hour | day | week} [burst byte_number bytes]

       A limit statement matches at a limited rate using a token bucket filter. A rule using this statement will match until this limit is reached. It can be used in combination with the log statement to give limited logging. The over
       keyword, that is optional, makes it match over the specified rate.

       limit statement values

       ┌──────────────┬───────────────────┬───────────────────────────┐
       │Value         │ Description       │ Type                      │
       ├──────────────┼───────────────────┼───────────────────────────┤
       │packet_number │ Number of packets │ unsigned integer (32 bit) │
       ├──────────────┼───────────────────┼───────────────────────────┤
       │byte_number   │ Number of bytes   │ unsigned integer (32 bit) │
       └──────────────┴───────────────────┴───────────────────────────┘


limit statement
	rate [over] <value> <unit> [burst <value> <unit>]	Rate limit
		limit rate 400/minute
		limit rate 400/hour
		limit rate over 40/day
		limit rate over 400/week
		limit rate over 1023/second burst 10 packets
		limit rate 1025 kbytes/second
		limit rate 1023000 mbytes/second
		limit rate 1025 bytes/second burst 512 bytes
		limit rate 1025 kbytes/second burst 1023 kbytes
		limit rate 1025 mbytes/second burst 1025 kbytes
		limit rate 1025000 mbytes/second burst 1023 mbytes
*/
type TStatementLimit struct {
	Expr TChainedExpressions

	//EQ      *TEquate
	//Verdict *TStatementVerdict
	//Counter *TStatementCounter
}

func (expr *TStatementLimit) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TStatementLimit) GetTokens() []TToken {
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

func (rule *TTextStatement) parseStatementLimit(iTokenIndexRO uint16) (*TStatementLimit, error) {
	var retExpr TStatementLimit
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenStatementLimit {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'limit' (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
