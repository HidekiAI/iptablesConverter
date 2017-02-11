package nftables

import (
	"fmt"
	"log"
	"path/filepath"
	"runtime"
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
type Tipv6Version uint8
type Tipv6Priority TToken
type Tipv6Dscp []TUInt8OrAlias
type Tipv6Ecn []TUInt8OrAlias
type Tipv6FlowLabel []TUInt32OrAlias
type Tipv6Length []TUInt16OrAlias
type Tipv6NextHdr []Tinetproto
type Tipv6HopLimit []uint8
type Tipv6SAddr [2]TIPAddress
type Tipv6DAddr [2]TIPAddress
type TExpressionHeaderIpv6 struct {
	Expr TChainedExpressions

	//Version   *uint8            // IP header version 4-bits
	//Priority  *string           // NOTE: type not documented on man page
	//Dscp      *[]TUInt8OrAlias  // Differentiated Service Code Point 6-bits
	//Ecn       *[]TUInt8OrAlias  // Explicit Congestion Notification 2-bits
	//Flowlabel *[]TUInt32OrAlias // 20-bits
	//Length    *[]TUInt16OrAlias // Payload length
	//Nexthdr   *[]Tinetproto
	//Hoplimit  *[]uint8
	//Saddr     *[2]TIPAddress // can be range-based with '-'
	//Daddr     *[2]TIPAddress // can be range-based with '-'
	//EQ        *TEquate
	//Verdict   *TStatementVerdict
	//Counter   *TStatementCounter
}

func (expr *TExpressionHeaderIpv6) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TExpressionHeaderIpv6) GetTokens() []TToken {
	var ret []TToken
	if expr.HasExpression() {
		for _, e := range expr.Expr.Expressions {
			switch tExpr := e.(type) {
			default:
				switch tE := e.(type) {
				case TStatementVerdict:
					ret = append(ret, GetTokens(tE)...)
				case TStatementLog:
					ret = append(ret, GetTokens(tE)...)
				case TStatementCounter:
					ret = append(ret, GetTokens(tE)...)
				case TEquate:
					ret = append(ret, GetTokens(tE)...)
				default:
					caller := ""
					// Caller(1) means the callee of this method (skip 1 stack)
					if _, f, ln, ok := runtime.Caller(1); ok {
						_, fn := filepath.Split(f)
						caller = fmt.Sprintf("%s:%d", fn, ln)
					}
					log.Panicf("%s: Unhandled type '%T' encountered (contents: '%+v')", caller, tE, tE)
				}
			}
		}
	}
	return ret
}

// IPv6 extension header expressions refer to data from an IPv6 packet's extension headers.
type TExpressionHeaderIpv6Ext struct { // IPv6 extension header
	Expr TChainedExpressions

	//EQ      *TEquate
	//Verdict *TStatementVerdict
	//Counter *TStatementCounter
}

func (expr *TExpressionHeaderIpv6Ext) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TExpressionHeaderIpv6Ext) GetTokens() []TToken {
	var ret []TToken
	if expr.HasExpression() {
		for _, e := range expr.Expr.Expressions {
			switch tExpr := e.(type) {
			default:
				switch tE := e.(type) {
				case TStatementVerdict:
					ret = append(ret, GetTokens(tE)...)
				case TStatementLog:
					ret = append(ret, GetTokens(tE)...)
				case TStatementCounter:
					ret = append(ret, GetTokens(tE)...)
				case TEquate:
					ret = append(ret, GetTokens(tE)...)
				default:
					caller := ""
					// Caller(1) means the callee of this method (skip 1 stack)
					if _, f, ln, ok := runtime.Caller(1); ok {
						_, fn := filepath.Split(f)
						caller = fmt.Sprintf("%s:%d", fn, ln)
					}
					log.Panicf("%s: Unhandled type '%T' encountered (contents: '%+v')", caller, tE, tE)
				}
			}
		}
	}
	return ret
}

func (rule *TTextStatement) parsePayloadIp6(iTokenIndexRO uint16) (*TExpressionHeaderIpv6, error) {
	var retExpr TExpressionHeaderIpv6
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchIP6 {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	case CTokenIPv6DSCP:
		{
			retExpr.Expr.SetSubType(tokens[0])
			//	dscp <value>
			//		ip6 dscp cs1
			//		ip6 dscp != cs1
			//		ip6 dscp 0x38
			//		ip6 dscp != 0x20
			//		ip6 dscp {cs0, cs1, cs2, cs3, cs4, cs5, cs6, cs7, af11, af12, af13, af21, af22, af23, af31, af32, af33, af41, af42, af43, ef}
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}

			// operands can be range of numbers or aliases in range ('-') and comma separated
			isNum, nl := tokens[0].tokenToInt() // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				// {a, b, c, d-g, h, i}
				tl := tokens[0].parseCommaSeparated()
				for _, t := range tl {
					if t[1] != "" {
						retExpr.Expr.Append(Tipv6Dscp{TUInt8OrAlias{Alias: &t[0]}, TUInt8OrAlias{Alias: &t[1]}})
					} else {
						retExpr.Expr.Append(Tipv6Dscp{TUInt8OrAlias{Alias: &t[0]}})
					}
					retExpr.Expr.AppendTokens(t[:])
				}
			} else {
				// can be single, ranged, or comma-separated
				for _, n := range nl {
					ui8 := uint8(n[0])
					retExpr.Expr.Append(Tipv6Dscp{TUInt8OrAlias{Num: &ui8}})
					retExpr.Expr.AppendToken(TToken(strconv.Itoa(n[0])))
					if len(n) == 1 {
					} else {
						ui81 := uint8(n[0])
						ui82 := uint8(n[1])
						retExpr.Expr.Append(Tipv6Dscp{TUInt8OrAlias{Num: &ui81}, TUInt8OrAlias{Num: &ui82}})
						retExpr.Expr.AppendTokens([]TToken{TToken(strconv.Itoa(n[0])), TToken(strconv.Itoa(n[1]))})
					}
				}
			}
		}
	case CTokenIPv6FlowLabel:
		{
			retExpr.Expr.SetSubType(tokens[0])
			//	flowlabel <label>	Flow label
			//		ip6 flowlabel 22
			//		ip6 flowlabel != 233
			//		ip6 flowlabel { 33, 55, 67, 88 }
			//		ip6 flowlabel { 33-55 }
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}

			// operands can be range of numbers or aliases in range ('-') and comma separated
			isNum, nl := tokens[0].tokenToInt() // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				// {a, b, c, d-g, h, i}
				tl := tokens[0].parseCommaSeparated()
				for _, t := range tl {
					retExpr.Expr.Append(Tipv6FlowLabel{TUInt32OrAlias{Alias: &t[0]}})
					if t[1] != "" {
						retExpr.Expr.Append(Tipv6FlowLabel{TUInt32OrAlias{Alias: &t[1]}})
					}
					retExpr.Expr.AppendTokens(t[:])
				}
			} else {
				// can be single, ranged, or comma-separated
				for _, n := range nl {
					if len(n) == 1 {
						ui32 := uint32(n[0])
						retExpr.Expr.Append(Tipv6FlowLabel{TUInt32OrAlias{Num: &ui32}})
						retExpr.Expr.AppendTokens([]TToken{TToken(strconv.Itoa(n[0]))})
					} else {
						ui32_1 := uint32(n[0])
						ui32_2 := uint32(n[1])
						retExpr.Expr.Append(Tipv6FlowLabel{TUInt32OrAlias{Num: &ui32_1}, TUInt32OrAlias{Num: &ui32_2}})
						retExpr.Expr.AppendTokens([]TToken{TToken(strconv.Itoa(n[0])), TToken(strconv.Itoa(n[1]))})
					}
				}
			}
		}
	case CTokenIPv6Length:
		{
			retExpr.Expr.SetSubType(tokens[0])
			//	length <length>	Payload length
			//		ip6 length 232
			//		ip6 length != 233
			//		ip6 length 333-435
			//		ip6 length != 333-453
			//		ip6 length { 333, 553, 673, 838}
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}

			// operands can be range of numbers or aliases in range ('-') and comma separated
			isNum, nl := tokens[0].tokenToInt() // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				// {a, b, c, d-g, h, i}
				tl := tokens[0].parseCommaSeparated()
				for _, t := range tl {
					retExpr.Expr.Append(Tipv6Length{TUInt16OrAlias{Alias: &t[0]}})
					if t[1] != "" {
						retExpr.Expr.Append(Tipv6Length{TUInt16OrAlias{Alias: &t[1]}})
					}
					retExpr.Expr.AppendTokens(t[:])
				}
			} else {
				// can be single, ranged, or comma-separated
				for _, n := range nl {
					if len(n) > 1 {

						retExpr.Expr.Append(Tipv6Length{TUInt16OrAlias{Range: &TMinMaxU16{uint16(n[0]), uint16(n[1])}}})
						retExpr.Expr.AppendTokens([]TToken{TToken(strconv.Itoa(n[0])), TToken(strconv.Itoa(n[1]))})
					} else {
						retExpr.Expr.Append(Tipv6Length{TUInt16OrAlias{Range: &TMinMaxU16{uint16(n[0])}}})
						retExpr.Expr.AppendTokens([]TToken{TToken(strconv.Itoa(n[0]))})
					}
				}
			}
		}
	case CTokenIPv6NextHdr:
		{
			retExpr.Expr.SetSubType(tokens[0])
			//	nexthdr <header>	Next header type (Upper layer protocol number)
			//		ip6 nexthdr {esp, udp, ah, comp, udplite, tcp, dccp, sctp, icmpv6}
			//		ip6 nexthdr esp
			//		ip6 nexthdr != esp
			//		ip6 nexthdr { 33-44 }
			//		ip6 nexthdr 33-44
			//		ip6 nexthdr != 33-44
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}

			// operands can be range of numbers or aliases in range ('-') and comma separated
			isNum, nl := tokens[0].tokenToInt() // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				// {a, b, c, d-g, h, i}
				tl := tokens[0].parseCommaSeparated()
				for _, t := range tl {
					retExpr.Expr.Append(Tipv6NextHdr{Tinetproto{Alias: &t[0]}})
					if t[1] != "" {
						retExpr.Expr.Append(Tipv6NextHdr{Tinetproto{Alias: &t[1]}})
					}
					retExpr.Expr.AppendTokens(t[:])
				}
			} else {
				// can be single, ranged, or comma-separated
				for _, n := range nl {
					retExpr.Expr.Append(Tipv6NextHdr{Tinetproto{Range: &TMinMaxU32{uint32(n[0]), uint32(n[1])}}})
					retExpr.Expr.AppendTokens([]TToken{TToken(strconv.Itoa(n[0])), TToken(strconv.Itoa(n[1]))})
				}
			}
		}
	case CTokenIPv6HopLimit:
		{
			retExpr.Expr.SetSubType(tokens[0])
			//	hoplimit <hoplimit>	Hop limit
			//		ip6 hoplimit 1
			//		ip6 hoplimit != 233
			//		ip6 hoplimit 33-45
			//		ip6 hoplimit != 33-45
			//		ip6 hoplimit {33, 55, 67, 88}
			//		ip6 hoplimit {33-55}
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}

			// operands can be range of numbers or aliases in range ('-') and comma separated
			isNum, nl := tokens[0].tokenToInt() // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				err = fmt.Errorf("Hoplimit parameters does not meet the syntax format; found %v when expecting numerical values", tokens[0])
			} else {
				// can be single, ranged, or comma-separated
				for _, n := range nl {
					if len(n) > 1 {
						retExpr.Expr.Append(Tipv6HopLimit{uint8(n[0]), uint8(n[1])})
						retExpr.Expr.AppendTokens([]TToken{TToken(strconv.Itoa(n[0])), TToken(strconv.Itoa(n[1]))})
					} else {
						retExpr.Expr.Append(Tipv6HopLimit{uint8(n[0])})
						retExpr.Expr.AppendTokens([]TToken{TToken(strconv.Itoa(n[0]))})
					}
				}
			}
		}
	case CTokenIPv6SAddr:
		{
			retExpr.Expr.SetSubType(tokens[0])
			//	saddr <ip source address>	Source Address
			//		ip6 saddr 1234:1234:1234:1234:1234:1234:1234:1234
			//		ip6 saddr ::1234:1234:1234:1234:1234:1234:1234
			//		ip6 saddr ::/64
			// Combination of saddr/daddr:
			//		ip6 saddr ::1 ip6 daddr ::2
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}

			a, ipErr := tokens[0].tokenToIP()
			err = ipErr
			if ipErr == nil {
				// there should be either single pair (ranged or single address)
				retExpr.Expr.Append(Tipv6SAddr(a[0]))
			}
		}
	case CTokenIPv6DAddr:
		{
			retExpr.Expr.SetSubType(tokens[0])
			//	daddr <ip destination address>	Destination Address
			//		ip6 daddr 1234:1234:1234:1234:1234:1234:1234:1234
			//		ip6 daddr != ::1234:1234:1234:1234:1234:1234:1234-1234:1234::1234:1234:1234:1234:1234
			// Combination of saddr/daddr:
			//		ip6 saddr ::1 ip6 daddr ::2
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}

			a, ipErr := tokens[0].tokenToIP()
			err = ipErr
			if ipErr == nil {
				// there should be either single pair (ranged or single address)
				retExpr.Expr.Append(Tipv6DAddr(a[0]))
			}
		}
	case CTokenIPv6Version:
		{
			retExpr.Expr.SetSubType(tokens[0])
			//	version <version>	IP header version
			//		ip6 version 6
			isNum, nl := tokens[0].tokenToInt() // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum {
				retExpr.Expr.Append(Tipv6Version(nl[0][0]))
			}
		}
	default:
		{
			log.Panicf("Unhandled token '%s' for 'ip6' (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}

func (rule *TTextStatement) parsePayloadIp6Ext(iTokenIndexRO uint16) (*TExpressionHeaderIpv6Ext, error) {
	var retExpr TExpressionHeaderIpv6Ext
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenStatementIP6Ext {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
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

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
