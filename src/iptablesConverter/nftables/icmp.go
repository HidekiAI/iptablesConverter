package nftables

import (
	"log"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Icmp
icmp match
	type <type>	ICMP packet type
		icmp type {echo-reply, destination-unreachable, source-quench, redirect, echo-request, time-exceeded, parameter-problem, timestamp-request, timestamp-reply, info-request, info-reply, address-mask-request, address-mask-reply, router-advertisement, router-solicitation}
	code	ICMP packet code
		icmp code 111
		icmp code != 33-55
		icmp code { 2, 4, 54, 33, 56}
	checksum <value>	ICMP packet checksum
		icmp checksum 12343
		icmp checksum != 11-343
		icmp checksum { 1111, 222, 343 }
	id <value>	ICMP packet id
		icmp id 12343
		icmp id != 11-343
		icmp id { 1111, 222, 343 }
	sequence <value>	ICMP packet sequence
		icmp sequence 12343
		icmp sequence != 11-343
		icmp sequence { 1111, 222, 343 }
	mtu <value>	ICMP packet mtu
		icmp mtu 12343
		icmp mtu != 11-343
		icmp mtu { 1111, 222, 343 }
	gateway <value>	ICMP packet gateway
		icmp gateway 12343
		icmp gateway != 11-343
		icmp gateway { 1111, 222, 343 }

*/
type TICMP struct {
	//EQ      TEquate
	Verdict TStatementVerdict
	Counter TStatementCounter
	Tokens  []TToken
}

func parsePayloadIcmp(rule *TTextStatement, iTokenIndexRO uint16) (TICMP, error) {
	var retExpr TICMP
	err, iTokenIndex, tokens, currentRule := getNextToken(rule, iTokenIndexRO, 1)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchICMP {
		retExpr.Tokens = append(retExpr.Tokens, tokens[0])
		err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'icmp' (in %+v)", tokens, rule)
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
