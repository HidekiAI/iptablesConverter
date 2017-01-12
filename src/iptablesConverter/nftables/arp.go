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
	//Verdict TStatementVerdict
	Tokens []TToken
}

func parsePayloadArp(rule *TTextStatement) *TExpressionHeaderArp {
	retArp := new(TExpressionHeaderArp)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchARP {
		retArp.Tokens = append(retArp.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'arp' (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented: %+v", rule)
	return nil
}
