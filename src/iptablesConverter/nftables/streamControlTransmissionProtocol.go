package nftables

import (
	"log"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Sctp
sctp match
	dport <destination port>	Destination port
		sctp dport 22
		sctp dport != 33-45
		sctp dport { 33-55 }
		sctp dport {telnet, http, https }
		sctp dport vmap { 22 : accept, 23 : drop }
		sctp dport vmap { 25:accept, 28:drop }
	sport < source port>	Source port
		sctp sport 22
		sctp sport != 33-45
		sctp sport { 33, 55, 67, 88}
		sctp sport { 33-55}
		sctp sport vmap { 25:accept, 28:drop }
		sctp sport 1024 tcp dport 22
	checksum <checksum>	Checksum
		sctp checksum 22
		sctp checksum != 33-45
		sctp checksum { 33, 55, 67, 88 }
		sctp checksum { 33-55 }
	vtag <tag>	Verification tag
		sctp vtag 22
		sctp vtag != 33-45
		sctp vtag { 33, 55, 67, 88 }
		sctp vtag { 33-55 }

*/

// sctp [SCTP header field]
type TExpressionHeaderSctp struct {
	Sport    Tinetservice
	Dport    Tinetservice
	Vtag     uint32 // Verification tag
	Checksum uint32

	//EQ      TEquate
	Verdict TStatementVerdict
	Counter TStatementCounter
	Tokens  []TToken
}

func parsePayloadSctp(rule *TTextStatement, iTokenIndexRO uint16) (TExpressionHeaderSctp, error) {
	var retExpr TExpressionHeaderSctp
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchSCTP {
		retExpr.Tokens = append(retExpr.Tokens, tokens[0])
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'sctp' (stream control transmission protocol) (in %+v)", tokens, rule)
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
