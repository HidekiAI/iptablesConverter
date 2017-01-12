package nftables

import (
	"log"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Udplite
udplite match
	dport <destination port>	Destination port
		udplite dport 22
		udplite dport != 33-45
		udplite dport { 33-55 }
		udplite dport {telnet, http, https }
		udplite dport vmap { 22 : accept, 23 : drop }
		udplite dport vmap { 25:accept, 28:drop }
	sport < source port>	Source port
		udplite sport 22
		udplite sport != 33-45
		udplite sport { 33, 55, 67, 88}
		udplite sport { 33-55}
		udplite sport vmap { 25:accept, 28:drop }
		udplite sport 1024 tcp dport 22
	checksum <checksum>	Checksum
		udplite checksum 22
		udplite checksum != 33-45
		udplite checksum { 33, 55, 67, 88 }
		udplite checksum { 33-55 }

*/

// udplite [UDP-Lite header field]
type TExpressionHeaderUdpLite struct {
	Sport    Tinetservice
	Dport    Tinetservice
	Cscov    uint16 // Checksum coverage
	Checksum uint16

	//EQ      TEquate
	//Verdict TStatementVerdict
	Tokens []TToken
}

func parsePayloadUdpLite(rule *TTextStatement) *TExpressionHeaderUdpLite {
	retUdpLite := new(TExpressionHeaderUdpLite)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchUDPLite {
		retUdpLite.Tokens = append(retUdpLite.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'udplite' (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented: %+v", rule)
	return nil
}
