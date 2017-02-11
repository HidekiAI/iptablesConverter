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
	Verdict TStatementVerdict
	Counter TStatementCounter
	Tokens  []TToken
}

func (rule *TTextStatement) parsePayloadAh(iTokenIndexRO uint16) (TExpressionHeaderAH, error) {
	var retExpr TExpressionHeaderAH
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchAH {
		retExpr.Tokens = append(retExpr.Tokens, tokens[0])
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'ah' (authentication header) (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter
	tokens, _, _, err = currentRule.getNextToken(iTokenIndex, 1, true)
	if err == nil {
		done := false
		for done == false {
			// verdits usually goes last, so always check 'counter' token first
			if currentRule.isCounterRule(iTokenIndex) {
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				if retExpr.Counter, err = currentRule.parseCounter(iTokenIndex); err == nil {
					// skip forward to next token
					tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
					if (err != nil) || (currentRule == nil) {
						err = nil // we're done
						done = true
						break
					}
				}
			} else if currentRule.isVerdict(iTokenIndex) {
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				if retExpr.Verdict, err = currentRule.parseVerdict(iTokenIndex); err == nil {
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
