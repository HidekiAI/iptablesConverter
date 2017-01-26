package nftables

import (
	"log"
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
type TExpressionHeaderUdp struct {
	Sport    Tinetservice
	Dport    Tinetservice
	Length   uint16
	Checksum uint16

	//EQ      TEquate
	Verdict TStatementVerdict
	Counter TStatementCounter
	Tokens  []TToken
}

func parsePayloadUdp(rule *TTextStatement, iTokenIndexRO uint16) (TExpressionHeaderUdp, error) {
	var retExpr TExpressionHeaderUdp
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchUDP {
		retExpr.Tokens = append(retExpr.Tokens, tokens[0])
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

	// now handle verdicts and counter
	tokens, _, _, err = currentRule.getNextToken(iTokenIndex, 1, true)
	if err == nil {
		done := false
		for done == false {
			// verdits usually goes last, so always check 'counter' token first
			if isCounterRule(currentRule, iTokenIndex) {
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				if retExpr.Counter, err = parseCounter(currentRule, iTokenIndex); err == nil {
					// skip forward to next token
					tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
					if (err != nil) || (currentRule == nil) {
						err = nil // we're done
						done = true
						break
					}
				}
			} else if isVerdict(currentRule, iTokenIndex) {
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				if retExpr.Verdict, err = parseVerdict(currentRule, iTokenIndex); err == nil {
					// skip forward to next token
					tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
					if (err != nil) || (currentRule == nil) {
						err = nil // we're done
						done = true
						break
					}
				}
			} else {
				err = nil // we're done
				done = true
				break
			}
		}
	} else {
		err = nil // we're done
	}
	return retExpr, err
}
