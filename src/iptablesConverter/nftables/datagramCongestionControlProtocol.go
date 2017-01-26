package nftables

import (
	"log"
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
type TExpressionHeaderDccp struct {
	Sport Tinetservice
	Dport Tinetservice

	//EQ      TEquate
	Verdict TStatementVerdict
	Counter TStatementCounter
	Tokens  []TToken
}

func parsePayloadDccp(rule *TTextStatement, iTokenIndexRO uint16) (TExpressionHeaderDccp, error) {
	var retExpr TExpressionHeaderDccp
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchDCCP {
		retExpr.Tokens = append(retExpr.Tokens, tokens[0])
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
