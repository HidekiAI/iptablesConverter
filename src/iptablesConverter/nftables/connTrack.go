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
	Helper     string     // Helper associated with the connection
	Label      Tctlabel   // Connection tracking label
	L3proto    Tnfproto   // Layer 3 protocol of the connection
	Saddr      TIPAddress // Source address of the connection for the given direction
	Daddr      TIPAddress // Destination address of the connection for the given direction
	Protocol   Tinetproto // Layer 4 protocol of the connection for the given direction
	ProtoSrc   uint16     // Layer 4 protocol source for the given direction
	ProtoDst   uint16     // Layer 4 protocol destination for the given direction
	Packets    uint64     // Packet count seen in the given direction or sum of original and reply
	Bytes      uint64     // Byte count seen

	EQ      TEquate
	Verdict TStatementVerdict
	Counter TStatementCounter
	Tokens  []TToken
}

func (rule *TTextStatement) parseConnTrack(iTokenIndexRO uint16) (TExpressionConntrack, error) {
	var retExpr TExpressionConntrack
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchCT {
		retExpr.Tokens = append(retExpr.Tokens, tokens[0])
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
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
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
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
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			log.Panicf("Unhandled token '%v' for 'ct expiration' (in %+v)", tokens, rule)
		}
	case CTokenCTHelper:
		{
			//	helper "<helper>"	Helper associated with the connection
			//		ct helper "ftp"
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
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
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
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
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			log.Panicf("Unhandled token '%v' for 'ct original|reply' (in %+v)", tokens, rule)
		}
	case CTokenCTState:
		{
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
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			}
			cs := parseCommaSeparated(tokens[0])
			for _, ccs := range cs {
				retExpr.State = append(retExpr.State, TConnTrackState(ccs[0]))
			}
		}
	case CTokenCTStatus:
		{
			//	status <status>	Status of the connection
			//		ct status expected
			//		ct status != expected
			//		ct status {expected,seen-reply,assured,confirmed,snat,dnat,dying}
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
			log.Panicf("Unhandled token '%v' for 'ct status' (in %+v)", tokens, rule)
		}
	default:
		{
			log.Panicf("Unhandled token '%v' for ct (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter
	var nextErr error
	if tokens, _, _, nextErr = currentRule.getNextToken(iTokenIndex, 1, true); nextErr == nil {
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
	}

	return retExpr, err
}
