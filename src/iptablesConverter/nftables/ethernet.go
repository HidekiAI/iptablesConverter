package nftables

import (
	"log"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Ether
ether match
	saddr <mac address>	Source mac address
		ether saddr 00:0f:54:0c:11:04
	type <type>
		ether type vlan
*/
type Tetheraddr string
type Tethertype string

// ether [ethernet header field]
type TExpressionHeaderEther struct {
	Daddr Tetheraddr // daddr	ether_addr	Destination MAC address
	Saddr Tetheraddr // saddr	ether_addr	Source MAC address
	Type  Tethertype // type	ether_type	EtherType

	//EQ      TEquate
	//Verdict TStatementVerdict
	Tokens []TToken
}

func parsePayloadEther(rule *TTextStatement) *TExpressionHeaderEther {
	retEther := new(TExpressionHeaderEther)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchEther {
		retEther.Tokens = append(retEther.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'ether' (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented: %+v", rule)
	return nil
}
