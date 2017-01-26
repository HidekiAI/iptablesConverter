package nftables

import (
	"log"
	"strconv"
)

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Tcp
tcp match
	dport <destination port>	Destination port
		tcp dport 22
		tcp dport != 33-45
		tcp dport { 33-55 }
		tcp dport {telnet, http, https }
		tcp dport vmap { 22 : accept, 23 : drop }
		tcp dport vmap { 25:accept, 28:drop }
	sport < source port>	Source port
		tcp sport 22
		tcp sport != 33-45
		tcp sport { 33, 55, 67, 88}
		tcp sport { 33-55}
		tcp sport vmap { 25:accept, 28:drop }
		tcp sport 1024 tcp dport 22
	sequence <value>	Sequence number
		tcp sequence 22
		tcp sequence != 33-45
	ackseq <value>	Acknowledgement number
		tcp ackseq 22
		tcp ackseq != 33-45
		tcp ackseq { 33, 55, 67, 88 }
		tcp ackseq { 33-55 }
	flags <flags>	TCP flags
		tcp flags { fin, syn, rst, psh, ack, urg, ecn, cwr}
		tcp flags cwr
		tcp flags != cwr
	window <value>	Window
		tcp window 22
		tcp window != 33-45
		tcp window { 33, 55, 67, 88 }
		tcp window { 33-55 }
	checksum <checksum>	IP header checksum
		tcp checksum 22
		tcp checksum != 33-45
		tcp checksum { 33, 55, 67, 88 }
		tcp checksum { 33-55 }
	urgptr <pointer>	Urgent pointer
		tcp urgptr 22
		tcp urgptr != 33-45
		tcp urgptr { 33, 55, 67, 88 }
	doff <offset>	Data offset
		tcp doff 8

*/
const (
	CTokenMatchTCPDPort      TToken = "dport"
	CTokenMatchTCPSPort      TToken = "sport"
	CTokenMatchTCPAckSeq     TToken = "ackseq"
	CTokenMatchTCPFlags      TToken = "flags"
	CTokenMatchTCPWin        TToken = "window"
	CTokenMatchTCPUrgentPtr  TToken = "urgptr"
	CTokenMatchTCPDataOffset TToken = "doff"
)

type Ttcpflags uint32 // tcp_flags

// tcp [TCP header field]
type TExpressionHeaderTcp struct {
	EQ        TEquate // i.e. 'iif != {"eth0", lo, "tun0"}'
	SportVMap []TVMap
	Sport     []Tinetservice
	DportVMap []TVMap
	Dport     []Tinetservice
	Sequence  uint32    // sequence number
	Ackseq    uint32    // Acknowledgement number
	Doff      uint8     // 4-bits data offset
	Reserved  uint8     // 4-bits reserved area
	Flags     Ttcpflags // tcp_flags
	Window    uint16
	Checksum  uint16
	Urgptr    uint16 // Urgetn pointer
	Meta      TExpressionMeta
	Counter   TStatementCounter
	Verdict   TStatementVerdict
	//EQ      TEquate
	Tokens []TToken
}

func parsePayloadTcp(rule *TTextStatement, iTokenIndexRO uint16) (TExpressionHeaderTcp, error) {
	var retExpr TExpressionHeaderTcp
	err, iTokenIndex, tokens, currentRule := getNextToken(rule, iTokenIndexRO, 1)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchTCP {
		retExpr.Tokens = append(retExpr.Tokens, tokens[0])
		err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}
	token := tokens[0]
	err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}

	switch token {
	case CTokenMatchTCPDPort:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			//dport <destination port>	Destination port
			//	tcp dport 22
			//	tcp dport != 33-45
			//	tcp dport { 33-55 }
			//	tcp dport {telnet, http, https }
			//	tcp dport vmap { 22 : accept, 23 : drop }
			//	tcp dport vmap { 25:accept, 28:drop }
			//  tcp dport ssh counter accept <-- need to handle meta token 'counter' and verdict 'accept' separate
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			retExpr.Dport = []Tinetservice{Tinetservice{ServicePort: [2]TToken{}}}
			if tokens[0] == CTokenVMap {
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
				if vmaps, err := parseVMap(tokens[0]); err == nil {
					for _, v := range vmaps {
						retExpr.DportVMap = append(retExpr.DportVMap, v)
					}
				}
			} else {
				// first, try it as number list
				isNum, nl := tokenToInt(tokens[0]) // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
				if isNum == false {
					// skgid {0, bin, sudo, daemon, usergrp1-usergrp5} - NOTE: ID=0 is root
					tl := parseCommaSeparated(tokens[0])
					for _, t := range tl {
						ti := Tinetservice{ServicePort: t}
						if p, perr := lookupServicePort(string(t[0])); perr == nil {
							ti.Port[0] = TPort(p)
						}
						if p, perr := lookupServicePort(string(t[1])); perr == nil {
							ti.Port[1] = TPort(p)
						}
						retExpr.Dport = append(retExpr.Dport, ti)
						retExpr.Tokens = append(retExpr.Tokens, t[:]...)
					}
				} else {
					// can be single, ranged, or comma-separated
					for _, n := range nl {
						ti := Tinetservice{Port: [2]TPort{TPort(n[0]), TPort(n[1])}}
						retExpr.Dport = append(retExpr.Dport, ti)
						retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[0])))
						if n[1] >= 0 {
							retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[1])))
						}
					}
				}
			}
		}
	case CTokenMatchTCPSPort:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			//sport < source port>	Source port
			//	tcp sport 22
			//	tcp sport != 33-45
			//	tcp sport { 33, 55, 67, 88}
			//	tcp sport { 33-55}
			//	tcp sport vmap { 25:accept, 28:drop }
			//	tcp sport 1024 tcp dport 22
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	case CTokenSequence:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			//sequence <value>	Sequence number
			//	tcp sequence 22
			//	tcp sequence != 33-45
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	case CTokenMatchTCPAckSeq:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			//ackseq <value>	Acknowledgement number
			//	tcp ackseq 22
			//	tcp ackseq != 33-45
			//	tcp ackseq { 33, 55, 67, 88 }
			//	tcp ackseq { 33-55 }
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	case CTokenMatchTCPFlags:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			//flags <flags>	TCP flags
			//	tcp flags { fin, syn, rst, psh, ack, urg, ecn, cwr}
			//	tcp flags cwr
			//	tcp flags != cwr
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
		}
	case CTokenMatchTCPWin:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			//window <value>	Window
			//	tcp window 22
			//	tcp window != 33-45
			//	tcp window { 33, 55, 67, 88 }
			//	tcp window { 33-55 }
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	case CTokenChecksum:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			//checksum <checksum>	IP header checksum
			//	tcp checksum 22
			//	tcp checksum != 33-45
			//	tcp checksum { 33, 55, 67, 88 }
			//	tcp checksum { 33-55 }
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
		}
	case CTokenMatchTCPUrgentPtr:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			//urgptr <pointer>	Urgent pointer
			//	tcp urgptr 22
			//	tcp urgptr != 33-45
			//	tcp urgptr { 33, 55, 67, 88 }
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
		}
	case CTokenMatchTCPDataOffset:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			//doff <offset>	Data offset
			//	tcp doff 8
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	default:
		{
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	}
	// now handle verdicts and counter
	err, _, tokens, _ = getNextToken(currentRule, iTokenIndex, 1)
	if err == nil {
		done := false
		for done == false {
			// verdits usually goes last, so always check 'counter' token first
			if isCounterRule(currentRule, iTokenIndex) {
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				if retExpr.Counter, err = parseCounter(currentRule, iTokenIndex); err == nil {
					// skip forward to next token
					err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
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
					err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
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
