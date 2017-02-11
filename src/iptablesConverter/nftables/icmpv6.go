package nftables

import (
	"fmt"
	"log"
	"strconv"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Icmpv6
icmpv6 match
	type <type>	ICMPv6 packet type
		icmpv6 type {destination-unreachable, packet-too-big, time-exceeded, echo-request, echo-reply, mld-listener-query, mld-listener-report, mld-listener-reduction, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect, parameter-problem, router-renumbering}
	code <code>	ICMPv6 packet code
		icmpv6 code 4
		icmpv6 code 3-66
		icmpv6 code {5, 6, 7}
	checksum <value>	ICMPv6 packet checksum
		icmpv6 checksum 12343
		icmpv6 checksum != 11-343
		icmpv6 checksum { 1111, 222, 343 }
	id <value>	ICMPv6 packet id
		icmpv6 id 12343
		icmpv6 id != 11-343
		icmpv6 id { 1111, 222, 343 }
	sequence <value>	ICMPv6 packet sequence
		icmpv6 sequence 12343
		icmpv6 sequence != 11-343
		icmpv6 sequence { 1111, 222, 343 }
	mtu <value>	ICMPv6 packet mtu
		icmpv6 mtu 12343
		icmpv6 mtu != 11-343
		icmpv6 mtu { 1111, 222, 343 }
	max-delay <value>	ICMPv6 packet max delay
		icmpv6 max-delay 33-45
		icmpv6 max-delay != 33-45
		icmpv6 max-delay {33, 55, 67, 88}
*/
const (
	CIcmpv6TokenCode     TToken = "code"
	CIcmpv6TokenMTU      TToken = "mtu"
	CIcmpv6TokenMaxDelay TToken = "max-delay"
)

type TICMPv6Type string

const (
	CIcmpv6TypeDestUnreach    TICMPv6Type = "destination-unreachable"
	CIcmpv6TypePacketTooBig   TICMPv6Type = "packet-too-big"
	CIcmpv6TypeTimeExcd       TICMPv6Type = "time-exceeded"
	CIcmpv6TypeEchoReq        TICMPv6Type = "echo-request"
	CIcmpv6TypeEchoRep        TICMPv6Type = "echo-reply"
	CIcmpv6TypeMldListnQ      TICMPv6Type = "mld-listener-query"
	CIcmpv6TypeMldListnRep    TICMPv6Type = "mld-listener-report"
	CIcmpv6TypeMldListnRed    TICMPv6Type = "mld-listener-reduction"
	CIcmpv6TypeNDRtrSolicit   TICMPv6Type = "nd-router-solicit"
	CIcmpv6TypeNDRtrAdv       TICMPv6Type = "nd-router-advert"
	CIcmpv6TypeNDNeighSolicit TICMPv6Type = "nd-neighbor-solicit"
	CIcmpv6TypeNDNeighAdv     TICMPv6Type = "nd-neighbor-advert"
	CIcmpv6TypeNDRedir        TICMPv6Type = "nd-redirect"
	CIcmpv6TypeParamProb      TICMPv6Type = "parameter-problem"
	CIcmpv6TypeRtrRenum       TICMPv6Type = "router-renumbering"
)

type TICMPv6 struct {
	Type     []TICMPv6Type
	Code     []TMinMaxU32
	Checksum []TMinMaxU32
	ID       []TMinMaxU32
	Sequence []TMinMaxU32
	MTU      []TMinMaxU32
	MaxDelay []TMinMaxU32
	EQ       TEquate
	Verdict  TStatementVerdict
	Counter  TStatementCounter
	Tokens   []TToken
}

func (rule *TTextStatement) parsePayloadIcmpv6(iTokenIndexRO uint16) (TICMPv6, error) {
	var retExpr TICMPv6
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchICMPv6 {
		retExpr.Tokens = append(retExpr.Tokens, tokens[0])
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	case CTokenType:
		{
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			//	type <type>	ICMPv6 packet type
			//		icmpv6 type {destination-unreachable, packet-too-big, time-exceeded, echo-request, echo-reply, mld-listener-query, mld-listener-report, mld-listener-reduction, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect, parameter-problem, router-renumbering}

		}
	case CIcmpv6TokenCode:
		{
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			//	code <code>	ICMPv6 packet code
			//		icmpv6 code 4
			//		icmpv6 code 3-66
			//		icmpv6 code {5, 6, 7}
		}
	case CTokenChecksum:
		{
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			//	checksum <value>	ICMPv6 packet checksum
			//		icmpv6 checksum 12343
			//		icmpv6 checksum != 11-343
			//		icmpv6 checksum { 1111, 222, 343 }
		}
	case CTokenID:
		{
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			//	id <value>	ICMPv6 packet id
			//		icmpv6 id 12343
			//		icmpv6 id != 11-343
			//		icmpv6 id { 1111, 222, 343 }
		}
	case CTokenSequence:
		{
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			//	sequence <value>	ICMPv6 packet sequence
			//		icmpv6 sequence 12343
			//		icmpv6 sequence != 11-343
			//		icmpv6 sequence { 1111, 222, 343 }
		}
	case CIcmpv6TokenMTU:
		{
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			//	mtu <value>	ICMPv6 packet mtu
			//		icmpv6 mtu 12343
			//		icmpv6 mtu != 11-343
			//		icmpv6 mtu { 1111, 222, 343 }
		}
	case CIcmpv6TokenMaxDelay:
		{
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			//	max-delay <value>	ICMPv6 packet max delay
			//		icmpv6 max-delay 33-45
			//		icmpv6 max-delay != 33-45
			//		icmpv6 max-delay {33, 55, 67, 88}
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				if tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true); err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			if len(retExpr.MaxDelay) == 0 {
				retExpr.MaxDelay = []TMinMaxU32{TMinMaxU32{}}
			}
			isNum, nl := tokenToInt(tokens[0]) // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum {
				// can be single, ranged, or comma-separated
				for _, n := range nl {
					tl := TMinMaxU32{uint32(n[0]), uint32(n[1])}
					retExpr.MaxDelay = append(retExpr.MaxDelay, tl)
					retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[0])))
					if n[1] >= 0 {
						retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[1])))
					}
				}
			} else {
				err = fmt.Errorf("Expected integer values for 'icmpv6 max-delay' parameters but instead found %v", tokens[0])
			}
		}
	default:
		{
			log.Panicf("Unhandled token '%v' for 'icmpv6' (in %+v)", tokens, rule)
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
