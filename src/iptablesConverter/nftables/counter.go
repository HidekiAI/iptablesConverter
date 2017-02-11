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
   COUNTER STATEMENT
       A counter statement sets the hit count of packets along with the number of bytes.

       counter {packets number } {bytes number }


counter statement
packets <packets> bytes <bytes>
	counter
	counter packets 0 bytes 0

*/
const (
	CTokenStatementCounterPackets TToken = "packets"
	CTokenStatementCounterBytes   TToken = "bytes"
)

type TcntrPackets int
type TcntrBytes int
type TStatementCounter struct {
	Expr TChainedExpressions

	//Packets *TPackets
	//Bytes   *TBytes
	//Verdict *TStatementVerdict
	//EQ      *TEquate
}

func (expr *TStatementCounter) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TStatementCounter) GetTokens() []TToken {
	var ret []TToken
	if expr.HasExpression() {
		for _, e := range expr.Expr.Expressions {
			switch tExpr := e.(type) {
			case TcntrPackets:
				ret = append(ret, GetTokens(tExpr)...)
			case TcntrBytes:
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

func IsCounterRule(token TToken) bool {
	caller := ""
	// Caller(1) means the callee of this method (skip 1 stack)
	if _, f, ln, ok := runtime.Caller(1); ok {
		_, fn := filepath.Split(f)
		caller = fmt.Sprintf("%s:%d", fn, ln)
	}

	if token == CTokenStatementCounter {
		if CLogLevel > CLogLevelDebug {
			log.Printf("\t\t\t>> %s: IsCounterRule(%s): true", caller, token)
		}
		return true
	}
	if CLogLevel > CLogLevelDebug {
		log.Printf("\t\t\t>> %s: IsCounterRule(%s): false", caller, token)
	}
	return false
}
func (rule *TTextStatement) isCounterRule(iTokenIndexRO uint16) bool {
	caller := ""
	// Caller(1) means the callee of this method (skip 1 stack)
	if _, f, ln, ok := runtime.Caller(1); ok {
		_, fn := filepath.Split(f)
		caller = fmt.Sprintf("%s:%d", fn, ln)
	}

	tokens, _, _, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("%s: Unable to find next token - %+v", caller, rule)
	}
	if CLogLevel > CLogLevelDebug {
		log.Printf("\t\t> %s: isCounterRule(%v) @ Index=%d: false", caller, tokens, iTokenIndexRO)
	}
	return IsCounterRule(tokens[0])
}

func (rule *TTextStatement) parseCounter(iTokenIndexRO uint16) (*TStatementCounter, error) {
	var retExpr TStatementCounter
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if IsCounterRule(tokens[0]) == false {
		log.Panicf("Token '%s' is not a counter expression - %+v", tokens[0], rule)
	}

	//packets <packets> bytes <bytes>
	//	counter
	//	counter packets 0 bytes 0
	//  counter log drop #'log' and 'drop' are a separate statement in which, it collects counter, logs it, then drops the payload
	tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndexRO, 1, true) // should be 'counter' token
	retExpr.Expr.SetType(tokens[0], rule.Depth)
	done := false
	for !done {
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			done = true
			break
		}
		retExpr.Expr.AppendTokens(tokens)
		isNum, n := tokens[0].tokenToInt()
		if isNum == false {
			done = true
			break
		}
		if tokens[0] == CTokenStatementCounterPackets {
			retExpr.Expr.Expressions = append(retExpr.Expr.Expressions, TctPackets(n[0][0]))
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				done = true
				break
			}
			retExpr.Expr.AppendTokens(tokens)
		} else if tokens[0] == CTokenStatementCounterPackets {
			retExpr.Expr.Expressions = append(retExpr.Expr.Expressions, TctBytes(n[0][0]))
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				done = true
				break
			}
			retExpr.Expr.AppendTokens(tokens)
		}
	}
	return &retExpr, err
}
