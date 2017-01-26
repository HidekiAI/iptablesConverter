package nftables

import (
	"log"
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
	if token == CTokenStatementCounter {
		return true
	}
	return false
}
func isCounterRule(rule *TTextStatement, iTokenIndexRO uint16) bool {
	err, _, tokens, _ := getNextToken(rule, iTokenIndexRO, 1)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	return IsCounterRule(tokens[0])
}

func parseCounter(rule *TTextStatement, iTokenIndexRO uint16) (TStatementCounter, error) {
	var retExpr TStatementCounter
	err, iTokenIndex, tokens, currentRule := getNextToken(rule, iTokenIndexRO, 1)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if IsCounterRule(tokens[0]) == false {
		log.Panicf("Token '%s' is not a counter expression - %+v", tokens[0], rule)
	}

	//packets <packets> bytes <bytes>
	//	counter
	//	counter packets 0 bytes 0
	err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndexRO, 1) // should be 'counter' token
	retExpr.Tokens = append(retExpr.Tokens, tokens[0])
	done := false
	for !done {
		err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
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
			err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if err != nil {
				done = true
				break
			}
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
		} else if tokens[0] == CTokenStatementCounterPackets {
			retExpr.Bytes = n[0][0]
			err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if err != nil {
				done = true
				break
			}
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
		}
	}
	return retExpr, err
}
