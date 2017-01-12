package nftables

import (
	"log"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Rt
rt match
	nexthdr <proto>	Next protocol header
		rt nexthdr { udplite, ipcomp, udp, ah, sctp, esp, dccp, tcp, ipv6-icmp }
		rt nexthdr 22
		rt nexthdr != 33-45
	hdrlength <length>	Header Length
		rt hdrlength 22
		rt hdrlength != 33-45
		rt hdrlength { 33, 55, 67, 88 }
	type <type>
		rt type 22
		rt type != 33-45
		rt type { 33, 55, 67, 88 }
	seg-left <value>
		rt seg-left 22
		rt seg-left != 33-45
		rt seg-left { 33, 55, 67, 88}

*/
type TRouting struct {
	//EQ      TEquate
	//Verdict TStatementVerdict
	Tokens []TToken
}

func parsePayloadRt(rule *TTextStatement) *TRouting {
	retRt := new(TRouting)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchRT {
		retRt.Tokens = append(retRt.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'rt' (routing) (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented: %+v", rule)
	return nil
}
