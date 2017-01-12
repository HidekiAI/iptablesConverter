package nftables

import (
	"log"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Vlan
vlan match
	id <value>	Vlan tag ID
		vlan id 4094
		vlan id 0
	cfi <value>
		vlan cfi 0
		vlan cfi 1
	pcp <value>
		vlan pcp 7
		vlan pcp 3

*/

// vlan [VLAN header field]
type TExpressionHeaderVlan struct {
	Id   uint16 // vlan id 12-bits
	Cfi  int    // canonical format indicator flag
	Pcp  uint8  // priority code point 3-bits
	Type Tethertype

	//EQ      TEquate
	//Verdict TStatementVerdict
	Tokens []TToken
}

func parsePayloadVlan(rule *TTextStatement) *TExpressionHeaderVlan {
	retVlan := new(TExpressionHeaderVlan)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchVLAN {
		retVlan.Tokens = append(retVlan.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'vlan' (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented: %+v", rule)
	return nil
}
