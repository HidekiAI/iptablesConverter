package nftables

import (
	"log"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Hbh
hbh match
	nexthdr <proto>	Next protocol header
		hbh nexthdr { udplite, comp, udp, ah, sctp, esp, dccp, tcp, icmpv6}
		hbh nexthdr 22
		hbh nexthdr != 33-45
	hdrlength <length>	Header Length
		hbh hdrlength 22
		hbh hdrlength != 33-45
		hbh hdrlength { 33, 55, 67, 88 }

*/
type THbh struct {
	//EQ      TEquate
	Verdict TStatementVerdict
	Counter TStatementCounter
	Tokens  []TToken
}

func parsePayloadHbh(rule *TTextStatement, iTokenIndexRO uint16) (THbh, error) {
	var retExpr THbh
	err, iTokenIndex, tokens, currentRule := getNextToken(rule, iTokenIndexRO, 1)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchHBH {
		retExpr.Tokens = append(retExpr.Tokens, tokens[0])
		err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'hbh' (hop by hop) (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter
	err, _, tokens, _ = getNextToken(currentRule, iTokenIndex, 1)
	if err == nil {
		done := false
		for done == false {
			// verdits usually goes last, so always check 'counter' token first
			if isCounterRule(currentRule, iTokenIndex) {
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				if retExpr.Counter, err = parseCounter(currentRule, iTokenIndex); err == nil {
					// skip forward to next token
					err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
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
					err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
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
