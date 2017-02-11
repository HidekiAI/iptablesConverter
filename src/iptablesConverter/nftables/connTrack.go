package nftables

import (
	"fmt"
	"log"
	"path/filepath"
	"runtime"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
   CONNTRACK STATEMENT
       The conntrack statement can be used to set the conntrack mark and conntrack labels.

       ct {mark | label} set value

       The ct statement sets meta data associated with a connection.

       Meta statement types

       ┌────────┬───────────────────────────┬───────┐
       │Keyword │ Description               │ Value │
       ├────────┼───────────────────────────┼───────┤
       │mark    │ Connection tracking mark  │ mark  │
       ├────────┼───────────────────────────┼───────┤
       │label   │ Connection tracking label │ label │
       └────────┴───────────────────────────┴───────┘
       save packet nfmark in conntrack

       ct set mark meta mark

*/
// ct {state | direction | status | mark | expiration | helper | label | bytes | packets} {original | reply | {l3proto | protocol | saddr | daddr | proto-src | proto-dst | bytes | packets}}
/*
Ct (ConnTrack)
ct match
	state <state>	State of the connection
		ct state { new, established, related, untracked }
		ct state != related
		ct state established
		ct state 8
	direction <value>	Direction of the packet relative to the connection
		ct direction original
		ct direction != original
		ct direction {reply, original}
	status <status>	Status of the connection
		ct status expected
		ct status != expected
		ct status {expected,seen-reply,assured,confirmed,snat,dnat,dying}
	mark [set]	Mark of the connection
		ct mark 0
		ct mark or 0x23 == 0x11
		ct mark or 0x3 != 0x1
		ct mark and 0x23 == 0x11
		ct mark and 0x3 != 0x1
		ct mark xor 0x23 == 0x11
		ct mark xor 0x3 != 0x1
		ct mark 0x00000032
		ct mark != 0x00000032
		ct mark 0x00000032-0x00000045
		ct mark != 0x00000032-0x00000045
		ct mark {0x32, 0x2222, 0x42de3}
		ct mark {0x32-0x2222, 0x4444-0x42de3}
		ct mark set 0x11 xor 0x1331
		ct mark set 0x11333 and 0x11
		ct mark set 0x12 or 0x11
		ct mark set 0x11
		ct mark set mark
		ct mark set mark map { 1 : 10, 2 : 20, 3 : 30 }
	expiration	Connection expiration time
		ct expiration 30
		ct expiration 30s
		ct expiration != 233
		ct expiration != 3m53s
		ct expiration 33-45
		ct expiration 33s-45s
		ct expiration != 33-45
		ct expiration != 33s-45s
		ct expiration {33, 55, 67, 88}
		ct expiration { 1m7s, 33s, 55s, 1m28s}
	helper "<helper>"	Helper associated with the connection
		ct helper "ftp"
	[original | reply] bytes <value>
		ct original bytes > 100000
		ct bytes > 100000
	[original | reply] packets <value>
		ct reply packets < 100
	[original | reply] saddr <ip source address>
		ct original saddr 192.168.0.1
		ct reply saddr 192.168.0.1
		ct original saddr 192.168.1.0/24
		ct reply saddr 192.168.1.0/24
	[original | reply] daddr <ip destination address>
		ct original daddr 192.168.0.1
		ct reply daddr 192.168.0.1
		ct original daddr 192.168.1.0/24
		ct reply daddr 192.168.1.0/24
	[original | reply] l3proto <protocol>
		ct original l3proto ipv4
	[original | reply] protocol <protocol>
		ct original protocol 6
	[original | reply] proto-dst <port>
		ct original proto-dst 22
	[original | reply] proto-src <port>
		ct reply proto-src 53
*/
const (
	// ct {state | direction | status | mark | expiration | helper | label | bytes | packets} {original | reply | {l3proto | protocol | saddr | daddr | proto-src | proto-dst | bytes | packets}}
	CTokenCTState  TToken = "state"
	CTokenCTDir    TToken = "direction"
	CTokenCTStatus TToken = "status"
	CTokenCTMark   TToken = "mark"
	CTokenCTExp    TToken = "expiration"
	CTokenCTHelper TToken = "helper"
	CTokenCTOrig   TToken = "original"
	CTokenCTReply  TToken = "reply"
)

type TConnTrackState TToken

const (
	TConnTrackStateEstablished TConnTrackState = "established"
	TConnTrackStateNew         TConnTrackState = "new"
	TConnTrackStateRelated     TConnTrackState = "related"
	TConnTrackStateUntracked   TConnTrackState = "untracked"
)

// {original | reply | {l3proto | protocol | saddr | daddr | proto-src | proto-dst | bytes | packets}}

type Tctstate []TConnTrackState
type Tctdir TTokenExpr
type Tctstatus TTokenExpr
type Tcttime TTokenExpr
type Tctlabel TTokenExpr
type TctSAddr TIPAddress
type TctDAddr TIPAddress
type TctProtoSrc uint16
type TctProtoDst uint16
type TctPackets uint64
type TctBytes uint64
type TctOrigReply struct {
	Expr TChainedExpressions

	//L3proto  *Tnfproto   // Layer 3 protocol of the connection
	//Protocol *Tinetproto // Layer 4 protocol of the connection for the given direction
	//Saddr    *TIPAddress // Source address of the connection for the given direction
	//Daddr    *TIPAddress // Destination address of the connection for the given direction
	//ProtoSrc *uint16     // Layer 4 protocol source for the given direction
	//ProtoDst *uint16     // Layer 4 protocol destination for the given direction
	//Packets  *uint64     // Packet count seen in the given direction or sum of original and reply
	//Bytes    *uint64     // Byte count seen
}
type TctHelper TTokenExpr
type TctOriginal TctOrigReply
type TctReply TctOrigReply
type TExpressionConntrack struct {
	Expr TChainedExpressions

	//State      *Tctstate // State of the connection
	//Direction  *Tctdir   // Direction of the packet relative to the connection
	//Status     *Tctstatus
	//Mark       *Tpacketmark
	//Expiration *Ttime
	//Helper     *THelper   // Helper associated with the connection
	//Label      *Tctlabel // Connection tracking label
	//Original   *TctOrigReply
	//Reply      *TctOrigReply
	//EQ         *TEquate
	//Verdict    *TStatementVerdict
	//Counter    *TStatementCounter
	//Log        *TStatementLog
}

func (expr *TExpressionConntrack) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TExpressionConntrack) GetTokens() []TToken {
	var ret []TToken
	if expr.HasExpression() {
		for _, e := range expr.Expr.Expressions {
			switch tExpr := e.(type) {
			//			case TConnTrackState:
			//				ret = append(ret, TToken(tExpr))
			case Tctstate: // State of the connection
				ret = append(ret, TToken("state"))
				for _, t := range tExpr {
					ret = append(ret, TToken(t))
				}
			case Tctdir: // Direction of the packet relative to the connection
				ret = append(ret, GetTokens(tExpr)...)
			case Tctstatus:
				ret = append(ret, GetTokens(tExpr)...)
			case Tpacketmark:
				ret = append(ret, GetTokens(tExpr)...)
			case Tctlabel: // Connection tracking label
				ret = append(ret, GetTokens(tExpr)...)
			case TctOrigReply:
				ret = append(ret, GetTokens(tExpr)...)
			case TctOriginal:
				ret = append(ret, GetTokens(tExpr)...)
			case TEquate:
				ret = append(ret, GetTokens(tExpr)...)
			case TStatementVerdict:
				ret = append(ret, GetTokens(tExpr)...)
			case TStatementCounter:
				ret = append(ret, GetTokens(tExpr)...)
			case TStatementLog:
				ret = append(ret, GetTokens(tExpr)...)
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

func (rule *TTextStatement) parseConnTrack(iTokenIndexRO uint16) (*TExpressionConntrack, error) {
	var retExpr TExpressionConntrack
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchCT {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	case CTokenCTDir:
		{
			retExpr.Expr.SetType(tokens[0], rule.Depth)
			//	direction <value>	Direction of the packet relative to the connection
			//		ct direction original
			//		ct direction != original
			//		ct direction {reply, original}
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retExpr.Expr.Append(new(Tctdir))
			log.Panicf("Unhandled token '%v' for 'ct direction' (in %+v)", tokens, rule)
		}
	case CTokenCTExp:
		{
			retExpr.Expr.SetType(tokens[0], rule.Depth)
			//	expiration	Connection expiration time
			//		ct expiration 30
			//		ct expiration 30s
			//		ct expiration != 233
			//		ct expiration != 3m53s
			//		ct expiration 33-45
			//		ct expiration 33s-45s
			//		ct expiration != 33-45
			//		ct expiration != 33s-45s
			//		ct expiration {33, 55, 67, 88}
			//		ct expiration { 1m7s, 33s, 55s, 1m28s}
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retExpr.Expr.AppendTokens(tokens)
			log.Panicf("Unhandled token '%v' for 'ct expiration' (in %+v)", tokens, rule)
		}
	case CTokenCTHelper:
		{
			retExpr.Expr.SetType(tokens[0], rule.Depth)
			//	helper "<helper>"	Helper associated with the connection
			//		ct helper "ftp"
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retExpr.Expr.AppendTokens(tokens)
			log.Panicf("Unhandled token '%v' for 'ct helper' (in %+v)", tokens, rule)
		}
	case CTokenCTMark:
		{
			retExpr.Expr.SetType(tokens[0], rule.Depth)
			//	mark [set]	Mark of the connection
			//		ct mark 0
			//		ct mark or 0x23 == 0x11
			//		ct mark or 0x3 != 0x1
			//		ct mark and 0x23 == 0x11
			//		ct mark and 0x3 != 0x1
			//		ct mark xor 0x23 == 0x11
			//		ct mark xor 0x3 != 0x1
			//		ct mark 0x00000032
			//		ct mark != 0x00000032
			//		ct mark 0x00000032-0x00000045
			//		ct mark != 0x00000032-0x00000045
			//		ct mark {0x32, 0x2222, 0x42de3}
			//		ct mark {0x32-0x2222, 0x4444-0x42de3}
			//		ct mark set 0x11 xor 0x1331
			//		ct mark set 0x11333 and 0x11
			//		ct mark set 0x12 or 0x11
			//		ct mark set 0x11
			//		ct mark set mark
			//		ct mark set mark map { 1 : 10, 2 : 20, 3 : 30 }
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retExpr.Expr.AppendTokens(tokens)
			log.Panicf("Unhandled token '%v' for 'ct mark' (in %+v)", tokens, rule)
		}
	case CTokenCTOrig, CTokenCTReply:
		{
			retExpr.Expr.SetType(tokens[0], rule.Depth)
			//	[original | reply] bytes <value>
			//		ct original bytes > 100000
			//		ct bytes > 100000
			//	[original | reply] packets <value>
			//		ct reply packets < 100
			//	[original | reply] saddr <ip source address>
			//		ct original saddr 192.168.0.1
			//		ct reply saddr 192.168.0.1
			//		ct original saddr 192.168.1.0/24
			//		ct reply saddr 192.168.1.0/24
			//	[original | reply] daddr <ip destination address>
			//		ct original daddr 192.168.0.1
			//		ct reply daddr 192.168.0.1
			//		ct original daddr 192.168.1.0/24
			//		ct reply daddr 192.168.1.0/24
			//	[original | reply] l3proto <protocol>
			//		ct original l3proto ipv4
			//	[original | reply] protocol <protocol>
			//		ct original protocol 6
			//	[original | reply] proto-dst <port>
			//		ct original proto-dst 22
			//	[original | reply] proto-src <port>
			//		ct reply proto-src 53
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retExpr.Expr.AppendTokens(tokens)
			log.Panicf("Unhandled token '%v' for 'ct original|reply' (in %+v)", tokens, rule)
		}
	case CTokenCTState:
		{
			retExpr.Expr.SetType(tokens[0], rule.Depth)

			//	state <state>	State of the connection
			//		ct state { new, established, related, untracked }
			//		ct state != related
			//		ct state established
			//		ct state 8
			// ct state != {
			//	new, untracked }
			//  counter accept
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
				retExpr.Expr.AppendTokens(tokens)
			}

			retExpr.Expr.AppendToken(CTokenOB)
			retExpr.Expr.AppendTokens(tokens)
			retExpr.Expr.AppendToken(CTokenCB)
			cs := tokens[0].parseCommaSeparated()
			for _, ccs := range cs {
				retExpr.Expr.Append(Tctstate{TConnTrackState(ccs[0])})
			}
		}
	case CTokenCTStatus:
		{
			retExpr.Expr.SetType(tokens[0], rule.Depth)
			//	status <status>	Status of the connection
			//		ct status expected
			//		ct status != expected
			//		ct status {expected,seen-reply,assured,confirmed,snat,dnat,dying}
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retExpr.Expr.AppendTokens(tokens)
			log.Panicf("Unhandled token '%v' for 'ct status' (in %+v)", tokens, rule)
		}
	default:
		{
			log.Panicf("Unhandled token '%v' for ct (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
