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

type TStatementCounter struct {
	Packets int
	Bytes   int

	//EQ      TEquate
	Verdict TStatementVerdict
	Tokens  []TToken
}

func IsCounterRule(token TToken) bool {
	caller := ""
	// Caller(1) means the callee of this method (skip 1 stack)
	if _, f, ln, ok := runtime.Caller(1); ok {
		_, fn := filepath.Split(f)
		caller = fmt.Sprintf("%s:%d", fn, ln)
	}

	if token == CTokenStatementCounter {
		if logLevel > 2 {
			log.Printf("\t\t\t>> %s: IsCounterRule(%s): true", caller, token)
		}
		return true
	}
	if logLevel > 2 {
		log.Printf("\t\t\t>> %s: IsCounterRule(%s): false", caller, token)
	}
	return false
}
func isCounterRule(rule *TTextStatement, iTokenIndexRO uint16) bool {
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
	if logLevel > 2 {
		log.Printf("\t\t> %s: isCounterRule(%v) @ Index=%d: false", caller, tokens, iTokenIndexRO)
	}
	return IsCounterRule(tokens[0])
}

func parseCounter(rule *TTextStatement, iTokenIndexRO uint16) (TStatementCounter, error) {
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
	tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndexRO, 1, true) // should be 'counter' token
	retExpr.Tokens = append(retExpr.Tokens, tokens[0])
	done := false
	for !done {
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			done = true
			break
		}
		retExpr.Tokens = append(retExpr.Tokens, tokens[0])
		isNum, n := tokenToInt(tokens[0])
		if isNum == false {
			done = true
			break
		}
		if tokens[0] == CTokenStatementCounterPackets {
			retExpr.Packets = n[0][0]
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				done = true
				break
			}
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
		} else if tokens[0] == CTokenStatementCounterPackets {
			retExpr.Bytes = n[0][0]
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				done = true
				break
			}
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
		}
	}
	return retExpr, err
}
