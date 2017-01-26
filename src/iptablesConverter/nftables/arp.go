package nftables

import (
	"log"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Arp
arp match
	ptype <value>	Payload type
		arp ptype 0x0800
	htype <value>	Header type
		arp htype 1
		arp htype != 33-45
		arp htype { 33, 55, 67, 88}
	hlen <length>	Header Length
		arp hlen 1
		arp hlen != 33-45
		arp hlen { 33, 55, 67, 88}
	plen <length>	Payload length
		arp plen 1
		arp plen != 33-45
		arp plen { 33, 55, 67, 88}
	operation <value>
		arp operation {nak, inreply, inrequest, rreply, rrequest, reply, request}

*/
// arp [ARP header field]
type Tarpop string
type TExpressionHeaderArp struct {
	Htype     uint16 // ARP hardware type
	Ptype     Tethertype
	Hlen      uint8
	Plen      uint8
	Operation Tarpop

	//EQ      TEquate
	Verdict TStatementVerdict
	Counter TStatementCounter
	Tokens  []TToken
}

func parsePayloadArp(rule *TTextStatement, iTokenIndexRO uint16) (TExpressionHeaderArp, error) {
	var retExpr TExpressionHeaderArp
	err, iTokenIndex, tokens, currentRule := getNextToken(rule, iTokenIndexRO, 1)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchARP {
		retExpr.Tokens = append(retExpr.Tokens, tokens[0])
		err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'arp' (in %+v)", tokens, rule)
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
