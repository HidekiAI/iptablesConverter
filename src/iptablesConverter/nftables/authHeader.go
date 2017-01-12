package nftables

import (
	"log"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Ah
ah match
	hdrlength <length>	AH header length
		ah hdrlength 11-23
		ah hdrlength != 11-23
		ah hdrlength {11, 23, 44 }
	reserved <value>
		ah reserved 22
		ah reserved != 33-45
		ah reserved {23, 100 }
		ah reserved { 33-55 }
	spi <value>
		ah spi 111
		ah spi != 111-222
		ah spi {111, 122 }
	sequence <sequence>	Sequence Number
		ah sequence 123
		ah sequence {23, 25, 33}
		ah sequence != 23-33

*/

// ah [AH header field]
type TExpressionHeaderAH struct { // authentication header
	Nexthdr   Tinetservice // Next header protocol
	Hdrlength uint8        // AH Header length
	Reserved  uint8        // Reserved area 4-bits
	Spi       uint32       // Security Parameter Index
	Sequence  uint32       // Sequence number

	//EQ      TEquate
	//Verdict TStatementVerdict
	Tokens []TToken
}

func parsePayloadAh(rule *TTextStatement) *TExpressionHeaderAH {
	retAH := new(TExpressionHeaderAH)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchAH {
		retAH.Tokens = append(retAH.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'ah' (authentication header) (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented: %+v", rule)
	return nil
}
