package nftables

import (
	"log"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Dst
dst match
	nexthdr <proto>	Next protocol header
		dst nexthdr { udplite, ipcomp, udp, ah, sctp, esp, dccp, tcp, ipv6-icmp}
		dst nexthdr 22
		dst nexthdr != 33-45
	hdrlength <length>	Header Length
		dst hdrlength 22
		dst hdrlength != 33-45
		dst hdrlength { 33, 55, 67, 88 }

*/
type TMatchDST struct {
	//EQ      TEquate
	//Verdict TStatementVerdict
	Tokens []TToken
}

func parsePayloadDst(rule *TTextStatement) *TMatchDST {
	retDst := new(TMatchDST)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchDST {
		retDst.Tokens = append(retDst.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'dst' (destination) (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented: %+v", rule)
	return nil
}
