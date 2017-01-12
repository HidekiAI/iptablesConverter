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
	//Verdict TStatementVerdict
	Tokens []TToken
}

func parseCounter(rule *TTextStatement) *TStatementCounter {
	retCtr := new(TStatementCounter)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenStatementCounter {
		retCtr.Tokens = append(retCtr.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	case CTokenStatementCounterPackets, CTokenStatementCounterBytes:
		{
			retCtr.Tokens = append(retCtr.Tokens, tokens[0])
			token := tokens[0]
			done := false
			for !done {
				haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if haveToken == false {
					done = true
					break
				}
				retCtr.Tokens = append(retCtr.Tokens, tokens[0])
				isNum, n := tokenToInt(tokens[0])
				if isNum == false {
					done = true
					break
				}
				if token == CTokenStatementCounterPackets {
					retCtr.Packets = n[0][0]
					haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
					if haveToken == false {
						done = true
						break
					}
					token = tokens[0]
					retCtr.Tokens = append(retCtr.Tokens, token)
				} else if token == CTokenStatementCounterPackets {
					retCtr.Bytes = n[0][0]
					haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
					if haveToken == false {
						done = true
						break
					}
					token = tokens[0]
					retCtr.Tokens = append(retCtr.Tokens, token)
				}
			}
		}
	default:
		{
			log.Panicf("Unhandled token '%v' for 'counter' (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented yet: %+v", rule)
	return nil
}
