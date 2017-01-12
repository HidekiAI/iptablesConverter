package nftables

import (
	"log"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
ip6 match
	dscp <value>
		ip6 dscp cs1
		ip6 dscp != cs1
		ip6 dscp 0x38
		ip6 dscp != 0x20
		ip6 dscp {cs0, cs1, cs2, cs3, cs4, cs5, cs6, cs7, af11, af12, af13, af21, af22, af23, af31, af32, af33, af41, af42, af43, ef}
	flowlabel <label>	Flow label
		ip6 flowlabel 22
		ip6 flowlabel != 233
		ip6 flowlabel { 33, 55, 67, 88 }
		ip6 flowlabel { 33-55 }
	length <length>	Payload length
		ip6 length 232
		ip6 length != 233
		ip6 length 333-435
		ip6 length != 333-453
		ip6 length { 333, 553, 673, 838}
	nexthdr <header>	Next header type (Upper layer protocol number)
		ip6 nexthdr {esp, udp, ah, comp, udplite, tcp, dccp, sctp, icmpv6}
		ip6 nexthdr esp
		ip6 nexthdr != esp
		ip6 nexthdr { 33-44 }
		ip6 nexthdr 33-44
		ip6 nexthdr != 33-44
	hoplimit <hoplimit>	Hop limit
		ip6 hoplimit 1
		ip6 hoplimit != 233
		ip6 hoplimit 33-45
		ip6 hoplimit != 33-45
		ip6 hoplimit {33, 55, 67, 88}
		ip6 hoplimit {33-55}
	saddr <ip source address>	Source Address
		ip6 saddr 1234:1234:1234:1234:1234:1234:1234:1234
		ip6 saddr ::1234:1234:1234:1234:1234:1234:1234
		ip6 saddr ::/64
		ip6 saddr ::1 ip6 daddr ::2
	daddr <ip destination address>	Destination Address
		ip6 daddr 1234:1234:1234:1234:1234:1234:1234:1234
		ip6 daddr != ::1234:1234:1234:1234:1234:1234:1234-1234:1234::1234:1234:1234:1234:1234
	version <version>	IP header version
		ip6 version 6
*/

// ip6 [IPv6 header field]
type TExpressionHeaderIpv6 struct {
	Version   uint8  // IP header version 4-bits
	Priority  string // NOTE: type not documented on man page
	Dscp      uint8  // Differentiated Service Code Point 6-bits
	Ecn       uint8  // Explicit Congestion Notification 2-bits
	Flowlabel uint32 // 20-bits
	Length    uint16 // Payload length
	Nexthdr   Tinetproto
	Hoplimit  uint8
	Saddr     Tipv6addr
	Daddr     Tipv6addr

	//EQ      TEquate
	//Verdict TStatementVerdict
	Tokens []TToken
}

// IPv6 extension header expressions refer to data from an IPv6 packet's extension headers.
type TExpressionHeaderIpv6Ext struct { // IPv6 extension header
	//EQ      TEquate
	//Verdict TStatementVerdict
	Tokens []TToken
}

func parsePayloadIp6(rule *TTextStatement) *TExpressionHeaderIpv6 {
	retIp6 := new(TExpressionHeaderIpv6)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchIP6 {
		retIp6.Tokens = append(retIp6.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%s' for 'ip6' (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented: %+v", rule)
	return nil
}

func parsePayloadIp6Ext(rule *TTextStatement) *TExpressionHeaderIpv6Ext {
	retIp6Ext := new(TExpressionHeaderIpv6Ext)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenStatementIP6Ext {
		retIp6Ext.Tokens = append(retIp6Ext.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 0)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%s' for 'ip6ext' (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented: %+v", rule)
	return nil
}
