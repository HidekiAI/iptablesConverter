package nftables

import (
	"fmt"
	"log"
	"strconv"
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
const (
	CTokenIPv6DSCP      TToken = "dscp"
	CTokenIPv6FlowLabel TToken = "flowlabel"
	CTokenIPv6Length    TToken = "length"
	CTokenIPv6NextHdr   TToken = "nexthdr"
	CTokenIPv6HopLimit  TToken = "hoplimit"
	CTokenIPv6SAddr     TToken = "saddr"
	CTokenIPv6DAddr     TToken = "daddr"
	CTokenIPv6Version   TToken = "version"
)

// ip6 [IPv6 header field]
type TExpressionHeaderIpv6 struct {
	Version   uint8            // IP header version 4-bits
	Priority  string           // NOTE: type not documented on man page
	Dscp      []TUInt8OrAlias  // Differentiated Service Code Point 6-bits
	Ecn       []TUInt8OrAlias  // Explicit Congestion Notification 2-bits
	Flowlabel []TUInt32OrAlias // 20-bits
	Length    []TUInt16OrAlias // Payload length
	Nexthdr   []Tinetproto
	Hoplimit  []uint8
	Saddr     [2]TIPAddress // can be range-based with '-'
	Daddr     [2]TIPAddress // can be range-based with '-'

	EQ      TEquate
	Verdict TStatementVerdict
	Counter TStatementCounter
	Tokens  []TToken
}

// IPv6 extension header expressions refer to data from an IPv6 packet's extension headers.
type TExpressionHeaderIpv6Ext struct { // IPv6 extension header
	//EQ      TEquate
	Verdict TStatementVerdict
	Counter TStatementCounter
	Tokens  []TToken
}

func parsePayloadIp6(rule *TTextStatement, iTokenIndexRO uint16) (TExpressionHeaderIpv6, error) {
	var retExpr TExpressionHeaderIpv6
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchIP6 {
		retExpr.Tokens = append(retExpr.Tokens, tokens[0])
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	case CTokenIPv6DSCP:
		{
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			//	dscp <value>
			//		ip6 dscp cs1
			//		ip6 dscp != cs1
			//		ip6 dscp 0x38
			//		ip6 dscp != 0x20
			//		ip6 dscp {cs0, cs1, cs2, cs3, cs4, cs5, cs6, cs7, af11, af12, af13, af21, af22, af23, af31, af32, af33, af41, af42, af43, ef}
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}

			retExpr.Dscp = []TUInt8OrAlias{}
			// operands can be range of numbers or aliases in range ('-') and comma separated
			isNum, nl := tokenToInt(tokens[0]) // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				// {a, b, c, d-g, h, i}
				tl := parseCommaSeparated(tokens[0])
				for _, t := range tl {
					retExpr.Dscp = append(retExpr.Dscp, TUInt8OrAlias{Alias: t[0]})
					if t[1] != "" {
						retExpr.Dscp = append(retExpr.Dscp, TUInt8OrAlias{Alias: t[1]})
					}
					retExpr.Tokens = append(retExpr.Tokens, t[:]...)
				}
			} else {
				// can be single, ranged, or comma-separated
				for _, n := range nl {
					retExpr.Dscp = append(retExpr.Dscp, TUInt8OrAlias{Num: uint8(n[0])})
					retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[0])))
					if n[1] >= 0 {
						retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[1])))
					}
				}
			}
		}
	case CTokenIPv6FlowLabel:
		{
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			//	flowlabel <label>	Flow label
			//		ip6 flowlabel 22
			//		ip6 flowlabel != 233
			//		ip6 flowlabel { 33, 55, 67, 88 }
			//		ip6 flowlabel { 33-55 }
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}

			retExpr.Flowlabel = []TUInt32OrAlias{}
			// operands can be range of numbers or aliases in range ('-') and comma separated
			isNum, nl := tokenToInt(tokens[0]) // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				// {a, b, c, d-g, h, i}
				tl := parseCommaSeparated(tokens[0])
				for _, t := range tl {
					retExpr.Flowlabel = append(retExpr.Flowlabel, TUInt32OrAlias{Alias: t[0]})
					if t[1] != "" {
						retExpr.Flowlabel = append(retExpr.Flowlabel, TUInt32OrAlias{Alias: t[1]})
					}
					retExpr.Tokens = append(retExpr.Tokens, t[:]...)
				}
			} else {
				// can be single, ranged, or comma-separated
				for _, n := range nl {
					if n[1] >= 0 {
						retExpr.Flowlabel = append(retExpr.Flowlabel, TUInt32OrAlias{Range: TMinMaxU32{uint32(n[0]), uint32(n[1])}})
						retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[1])))
					} else {
						retExpr.Flowlabel = append(retExpr.Flowlabel, TUInt32OrAlias{Num: uint32(n[0])})
						retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[0])))
					}
				}
			}
		}
	case CTokenIPv6Length:
		{
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			//	length <length>	Payload length
			//		ip6 length 232
			//		ip6 length != 233
			//		ip6 length 333-435
			//		ip6 length != 333-453
			//		ip6 length { 333, 553, 673, 838}
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}

			retExpr.Length = []TUInt16OrAlias{}
			// operands can be range of numbers or aliases in range ('-') and comma separated
			isNum, nl := tokenToInt(tokens[0]) // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				// {a, b, c, d-g, h, i}
				tl := parseCommaSeparated(tokens[0])
				for _, t := range tl {
					retExpr.Length = append(retExpr.Length, TUInt16OrAlias{Alias: t[0]})
					if t[1] != "" {
						retExpr.Length = append(retExpr.Length, TUInt16OrAlias{Alias: t[1]})
					}
					retExpr.Tokens = append(retExpr.Tokens, t[:]...)
				}
			} else {
				// can be single, ranged, or comma-separated
				for _, n := range nl {
					if n[1] >= 0 {
						retExpr.Length = append(retExpr.Length, TUInt16OrAlias{Range: TMinMaxU16{uint16(n[0]), uint16(n[1])}})
						retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[1])))
					} else {
						retExpr.Length = append(retExpr.Length, TUInt16OrAlias{Num: uint16(n[0])})
						retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[0])))
					}
				}
			}
		}
	case CTokenIPv6NextHdr:
		{
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			//	nexthdr <header>	Next header type (Upper layer protocol number)
			//		ip6 nexthdr {esp, udp, ah, comp, udplite, tcp, dccp, sctp, icmpv6}
			//		ip6 nexthdr esp
			//		ip6 nexthdr != esp
			//		ip6 nexthdr { 33-44 }
			//		ip6 nexthdr 33-44
			//		ip6 nexthdr != 33-44
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}

			retExpr.Nexthdr = []Tinetproto{}
			// operands can be range of numbers or aliases in range ('-') and comma separated
			isNum, nl := tokenToInt(tokens[0]) // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				// {a, b, c, d-g, h, i}
				tl := parseCommaSeparated(tokens[0])
				for _, t := range tl {
					retExpr.Nexthdr = append(retExpr.Nexthdr, Tinetproto{Alias: t[0]})
					if t[1] != "" {
						retExpr.Nexthdr = append(retExpr.Nexthdr, Tinetproto{Alias: t[1]})
					}
					retExpr.Tokens = append(retExpr.Tokens, t[:]...)
				}
			} else {
				// can be single, ranged, or comma-separated
				for _, n := range nl {
					retExpr.Nexthdr = append(retExpr.Nexthdr, Tinetproto{Range: TMinMaxU32{uint32(n[0]), uint32(n[1])}})
					retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[0])))
					if n[1] >= 0 {
						retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[1])))
					}
				}
			}
		}
	case CTokenIPv6HopLimit:
		{
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			//	hoplimit <hoplimit>	Hop limit
			//		ip6 hoplimit 1
			//		ip6 hoplimit != 233
			//		ip6 hoplimit 33-45
			//		ip6 hoplimit != 33-45
			//		ip6 hoplimit {33, 55, 67, 88}
			//		ip6 hoplimit {33-55}
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}

			retExpr.Hoplimit = []uint8{}
			// operands can be range of numbers or aliases in range ('-') and comma separated
			isNum, nl := tokenToInt(tokens[0]) // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				err = fmt.Errorf("Hoplimit parameters does not meet the syntax format; found %v when expecting numerical values", tokens[0])
			} else {
				// can be single, ranged, or comma-separated
				for _, n := range nl {
					if n[1] >= 0 {
						retExpr.Hoplimit = append(retExpr.Hoplimit, []uint8{uint8(n[0]), uint8(n[1])}...)
						retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[1])))
					} else {
						retExpr.Hoplimit = append(retExpr.Hoplimit, uint8(n[0]))
						retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[0])))
					}
				}
			}
		}
	case CTokenIPv6SAddr:
		{
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			//	saddr <ip source address>	Source Address
			//		ip6 saddr 1234:1234:1234:1234:1234:1234:1234:1234
			//		ip6 saddr ::1234:1234:1234:1234:1234:1234:1234
			//		ip6 saddr ::/64
			// Combination of saddr/daddr:
			//		ip6 saddr ::1 ip6 daddr ::2
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}

			retExpr.Saddr = [2]TIPAddress{}
			a, ipErr := tokenToIP(tokens[0])
			err = ipErr
			if ipErr == nil {
				// there should be either single pair (ranged or single address)
				retExpr.Saddr = a[0]
			}
		}
	case CTokenIPv6DAddr:
		{
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			//	daddr <ip destination address>	Destination Address
			//		ip6 daddr 1234:1234:1234:1234:1234:1234:1234:1234
			//		ip6 daddr != ::1234:1234:1234:1234:1234:1234:1234-1234:1234::1234:1234:1234:1234:1234
			// Combination of saddr/daddr:
			//		ip6 saddr ::1 ip6 daddr ::2
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}

			retExpr.Daddr = [2]TIPAddress{}
			a, ipErr := tokenToIP(tokens[0])
			err = ipErr
			if ipErr == nil {
				// there should be either single pair (ranged or single address)
				retExpr.Daddr = a[0]
			}
		}
	case CTokenIPv6Version:
		{
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			//	version <version>	IP header version
			//		ip6 version 6
		}
	default:
		{
			log.Panicf("Unhandled token '%s' for 'ip6' (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter
	tokens, _, _, err = currentRule.getNextToken(iTokenIndex, 1, true)
	if err == nil {
		done := false
		for done == false {
			// verdits usually goes last, so always check 'counter' token first
			if isCounterRule(currentRule, iTokenIndex) {
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				if retExpr.Counter, err = parseCounter(currentRule, iTokenIndex); err == nil {
					// skip forward to next token
					tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
					if (err != nil) || (currentRule == nil) {
						err = nil // we're done
						done = true
						break
					}
				}
			} else if isVerdict(currentRule, iTokenIndex) {
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				if retExpr.Verdict, err = parseVerdict(currentRule, iTokenIndex); err == nil {
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

func parsePayloadIp6Ext(rule *TTextStatement, iTokenIndexRO uint16) (TExpressionHeaderIpv6Ext, error) {
	var retExpr TExpressionHeaderIpv6Ext
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenStatementIP6Ext {
		retExpr.Tokens = append(retExpr.Tokens, tokens[0])
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%s' for 'ip6ext' (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter
	tokens, _, _, err = currentRule.getNextToken(iTokenIndex, 1, true)
	if err == nil {
		done := false
		for done == false {
			// verdits usually goes last, so always check 'counter' token first
			if isCounterRule(currentRule, iTokenIndex) {
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				if retExpr.Counter, err = parseCounter(currentRule, iTokenIndex); err == nil {
					// skip forward to next token
					tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
					if (err != nil) || (currentRule == nil) {
						err = nil // we're done
						done = true
						break
					}
				}
			} else if isVerdict(currentRule, iTokenIndex) {
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				if retExpr.Verdict, err = parseVerdict(currentRule, iTokenIndex); err == nil {
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
