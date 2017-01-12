package nftables

import (
	"log"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Hbh
hbh match
	nexthdr <proto>	Next protocol header
		hbh nexthdr { udplite, comp, udp, ah, sctp, esp, dccp, tcp, icmpv6}
		hbh nexthdr 22
		hbh nexthdr != 33-45
	hdrlength <length>	Header Length
		hbh hdrlength 22
		hbh hdrlength != 33-45
		hbh hdrlength { 33, 55, 67, 88 }

*/
type THbh struct {
	//EQ      TEquate
	//Verdict TStatementVerdict
	Tokens []TToken
}

func parsePayloadHbh(rule *TTextStatement) *THbh {
	retHbh := new(THbh)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchHBH {
		retHbh.Tokens = append(retHbh.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'hbh' (hop by hop) (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented: %+v", rule)
	return nil
}
