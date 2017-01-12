package nftables

import (
	"log"
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

type TConnTrackState string

const (
	TConnTrackStateEstablished TConnTrackState = "established"
	TConnTrackStateNew         TConnTrackState = "new"
	TConnTrackStateRelated     TConnTrackState = "related"
	TConnTrackStateUntracked   TConnTrackState = "untracked"
)

type Tctstate []TConnTrackState
type Tctdir string
type Tctstatus string
type Ttime string
type Tctlabel string
type TExpressionConntrack struct {
	State      Tctstate // State of the connection
	Direction  Tctdir   // Direction of the packet relative to the connection
	Status     Tctstatus
	Mark       Tpacketmark
	Expiration Ttime
	Helper     string   // Helper associated with the connection
	Label      Tctlabel // Connection tracking label
	L3proto    Tnfproto // Layer 3 protocol of the connection
	Saddr      struct { // Source address of the connection for the given direction
		Ipv4addr Tipv4addr
		Ipv6addr Tipv6addr
	}
	Daddr struct { // Destination address of the connection for the given direction
		Ipv4addr Tipv4addr
		Ipv6addr Tipv6addr
	}
	Protocol Tinetproto // Layer 4 protocol of the connection for the given direction
	ProtoSrc uint16     // Layer 4 protocol source for the given direction
	ProtoDst uint16     // Layer 4 protocol destination for the given direction
	Packets  uint64     // Packet count seen in the given direction or sum of original and reply
	Bytes    uint64     // Byte count seen

	EQ      TEquate
	Verdict TStatementVerdict
	Tokens  []TToken
}

func parseConnTrack(rule *TTextStatement) *TExpressionConntrack {
	retCT := new(TExpressionConntrack)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchCT {
		retCT.Tokens = append(retCT.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	case CTokenCTDir:
		{
			//	direction <value>	Direction of the packet relative to the connection
			//		ct direction original
			//		ct direction != original
			//		ct direction {reply, original}
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken == false {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retCT.Tokens = append(retCT.Tokens, tokens[0])
			log.Panicf("Unhandled token '%v' for 'ct direction' (in %+v)", tokens, rule)
		}
	case CTokenCTExp:
		{
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
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken == false {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retCT.Tokens = append(retCT.Tokens, tokens[0])
			log.Panicf("Unhandled token '%v' for 'ct expiration' (in %+v)", tokens, rule)
		}
	case CTokenCTHelper:
		{
			//	helper "<helper>"	Helper associated with the connection
			//		ct helper "ftp"
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken == false {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retCT.Tokens = append(retCT.Tokens, tokens[0])
			log.Panicf("Unhandled token '%v' for 'ct helper' (in %+v)", tokens, rule)
		}
	case CTokenCTMark:
		{
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
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken == false {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retCT.Tokens = append(retCT.Tokens, tokens[0])
			log.Panicf("Unhandled token '%v' for 'ct mark' (in %+v)", tokens, rule)
		}
	case CTokenCTOrig, CTokenCTReply:
		{
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
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken == false {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retCT.Tokens = append(retCT.Tokens, tokens[0])
			log.Panicf("Unhandled token '%v' for 'ct original|reply' (in %+v)", tokens, rule)
		}
	case CTokenCTState:
		{
			//	state <state>	State of the connection
			//		ct state { new, established, related, untracked }
			//		ct state != related
			//		ct state established
			//		ct state 8
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken == false {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retCT.Tokens = append(retCT.Tokens, tokens[0])
			if isEq, e := parseEquates(tokens[0]); isEq {
				retCT.EQ = e
				haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if haveToken == false {
					log.Panicf("Unable to find next token - %+v", rule)
				}
				retCT.Tokens = append(retCT.Tokens, tokens[0])
			}
			cs := parseCommaSeparated(tokens[0])
			for _, ccs := range cs {
				retCT.State = append(retCT.State, TConnTrackState(ccs))
			}

			lastRule := currentRule
			lastIndex := iTokenIndex
			// ct state != {
			//	new, untracked }
			//  counter accept
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken {
				retCT.Tokens = append(retCT.Tokens, tokens[0])
				// see if it is verdict or other expressions
				if IsVerdict(tokens[0]) {
					retCT.Verdict = parseVerdict(lastRule, int(lastIndex))
					haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				} else {
					log.Panicf("Unhandled token '%v' found in expression '%+v'", tokens, currentRule)
				}
			}
			return retCT
		}
	case CTokenCTStatus:
		{
			//	status <status>	Status of the connection
			//		ct status expected
			//		ct status != expected
			//		ct status {expected,seen-reply,assured,confirmed,snat,dnat,dying}
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken == false {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retCT.Tokens = append(retCT.Tokens, tokens[0])
			log.Panicf("Unhandled token '%v' for 'ct status' (in %+v)", tokens, rule)
		}
	default:
		{
			log.Panicf("Unhandled token '%v' for ct (in %+v)", tokens, rule)
		}
	}

	return nil
}
