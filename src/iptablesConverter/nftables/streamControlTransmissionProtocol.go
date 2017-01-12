package nftables

import (
	"log"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Sctp
sctp match
	dport <destination port>	Destination port
		sctp dport 22
		sctp dport != 33-45
		sctp dport { 33-55 }
		sctp dport {telnet, http, https }
		sctp dport vmap { 22 : accept, 23 : drop }
		sctp dport vmap { 25:accept, 28:drop }
	sport < source port>	Source port
		sctp sport 22
		sctp sport != 33-45
		sctp sport { 33, 55, 67, 88}
		sctp sport { 33-55}
		sctp sport vmap { 25:accept, 28:drop }
		sctp sport 1024 tcp dport 22
	checksum <checksum>	Checksum
		sctp checksum 22
		sctp checksum != 33-45
		sctp checksum { 33, 55, 67, 88 }
		sctp checksum { 33-55 }
	vtag <tag>	Verification tag
		sctp vtag 22
		sctp vtag != 33-45
		sctp vtag { 33, 55, 67, 88 }
		sctp vtag { 33-55 }

*/

// sctp [SCTP header field]
type TExpressionHeaderSctp struct {
	Sport    Tinetservice
	Dport    Tinetservice
	Vtag     uint32 // Verification tag
	Checksum uint32

	//EQ      TEquate
	//Verdict TStatementVerdict
	Tokens []TToken
}

func parsePayloadSctp(rule *TTextStatement) *TExpressionHeaderSctp {
	retSctp := new(TExpressionHeaderSctp)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchSCTP {
		retSctp.Tokens = append(retSctp.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'sctp' (stream control transmission protocol) (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented: %+v", rule)
	return nil
}
