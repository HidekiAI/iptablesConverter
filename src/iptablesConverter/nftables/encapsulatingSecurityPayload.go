package nftables

import (
	"log"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Esp
esp match
	spi <value>
		esp spi 111
		esp spi != 111-222
		esp spi {111, 122 }
	sequence <sequence>	Sequence Number
		esp sequence 123
		esp sequence {23, 25, 33}
		esp sequence != 23-33

*/
// esp [ESP header field]
type TExpressionHeaderESP struct { // encrypted security payload
	Spi      uint32 // Security Parameter Index
	Sequence uint32 // Sequence number

	//EQ      TEquate
	//Verdict TStatementVerdict
	Tokens []TToken
}

func parsePayloadEsp(rule *TTextStatement) *TExpressionHeaderESP {
	retEsp := new(TExpressionHeaderESP)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchESP {
		retEsp.Tokens = append(retEsp.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'esp' (encaplusating security payload) (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented: %+v", rule)
	return nil
}
