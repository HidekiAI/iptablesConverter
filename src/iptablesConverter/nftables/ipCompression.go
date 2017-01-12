package nftables

import (
	"log"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Comp
comp match
	nexthdr <protocol>	Next header protocol (Upper layer protocol)
		comp nexthdr != esp
		comp nexthdr {esp, ah, comp, udp, udplite, tcp, tcp, dccp, sctp}
	flags <flags>	Flags
		comp flags 0x0
		comp flags != 0x33-0x45
		comp flags {0x33, 0x55, 0x67, 0x88}
	cpi <value>	Compression Parameter Index
		comp cpi 22
		comp cpi != 33-45
		comp cpi {33, 55, 67, 88}

*/

type Tbitmask uint

// comp [IPComp header field]
type TExpressionHeaderIpcomp struct {
	Nexthdr Tinetservice // Next header protocol
	Flags   Tbitmask
	Cpi     uint16 // Compression Parameter Index

	//EQ      TEquate
	//Verdict TStatementVerdict
	Tokens []TToken
}

func parsePayloadIpComp(rule *TTextStatement) *TExpressionHeaderIpcomp {
	retComp := new(TExpressionHeaderIpcomp)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchComp {
		retComp.Tokens = append(retComp.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'comp' (ip compression) (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented: %+v", rule)
	return nil
}
