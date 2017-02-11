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
type TtcpSportVmap []TVMap
type TtcpDportVmap []TVMap
type TtcpSport []Tinetservice
type TtcpDport []Tinetservice
type TtcpSeq uint32
type TtcpAckSeq uint32
type TtcpDoff uint8
type TtcpReserved uint8
type TtcpFlags Ttcpflags
type TtcpWindow uint16
type TtcpChecksum uint16
type TtcpUrgPtr uint16
type TExpressionHeaderTcp struct {
	Expr TChainedExpressions

	//EQ        *TEquate // i.e. 'iif != {"eth0", lo, "tun0"}'
	//SportVMap *[]TVMap
	//Sport     *[]Tinetservice
	//DportVMap *[]TVMap
	//Dport     *[]Tinetservice
	//Sequence  *uint32    // sequence number
	//Ackseq    *uint32    // Acknowledgement number
	//Doff      *uint8     // 4-bits data offset
	//Reserved  *uint8     // 4-bits reserved area
	//Flags     *Ttcpflags // tcp_flags
	//Window    *uint16
	//Checksum  *uint16
	//Urgptr    *uint16 // Urgetn pointer
	//Meta      *TExpressionMeta
	//Counter   *TStatementCounter
	//Verdict   *TStatementVerdict
}

func (expr *TExpressionHeaderTcp) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TExpressionHeaderTcp) GetTokens() []TToken {
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

func (rule *TTextStatement) parsePayloadTcp(iTokenIndexRO uint16) (*TExpressionHeaderTcp, error) {
	var retExpr TExpressionHeaderTcp
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchTCP {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}
	token := tokens[0]
	tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}

	switch token {
	case CTokenMatchTCPDPort:
		{
			// TODO: How do I know that next interface{} is 'tcp dport'?
			retExpr.Expr.SetSubType(token)
			//dport <destination port>	Destination port
			//	tcp dport 22
			//	tcp dport != 33-45
			//	tcp dport { 33-55 }
			//	tcp dport {telnet, http, https }
			//	tcp dport vmap { 22 : accept, 23 : drop }
			//	tcp dport vmap { 25:accept, 28:drop }
			//  tcp dport ssh counter accept <-- need to handle meta token 'counter' and verdict 'accept' separate
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			if tokens[0] == CTokenVMap {
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
				if vmaps, err := tokens[0].parseVMap(); err == nil {
					for _, v := range vmaps {
						retExpr.Expr.Append(v)
					}
				}
			} else {
				// first, try it as number list
				isNum, nl := tokens[0].tokenToInt() // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
				if isNum == false {
					// skgid {0, bin, sudo, daemon, usergrp1-usergrp5} - NOTE: ID=0 is root
					tl := tokens[0].parseCommaSeparated()
					for _, t := range tl {
						ti := Tinetservice{ServicePort: &t}
						ti.Port = new([2]TPort)
						if p, perr := lookupServicePort(string(t[0])); perr == nil {
							ti.Port[0] = TPort(p)
						}
						if p, perr := lookupServicePort(string(t[1])); perr == nil {
							ti.Port[1] = TPort(p)
						}
						retExpr.Expr.Append(ti)
						retExpr.Expr.AppendTokens(t[:])
					}
				} else {
					// can be single, ranged, or comma-separated
					for _, n := range nl {
						ti := Tinetservice{Port: &[2]TPort{TPort(n[0]), TPort(n[1])}}
						retExpr.Expr.Append(ti)
						retExpr.Expr.AppendTokens([]TToken{TToken(strconv.Itoa(n[0])), TToken(strconv.Itoa(n[1]))})
					}
				}
			}
		}
	case CTokenMatchTCPSPort:
		{
			retExpr.Expr.SetSubType(token)
			//sport < source port>	Source port
			//	tcp sport 22
			//	tcp sport != 33-45
			//	tcp sport { 33, 55, 67, 88}
			//	tcp sport { 33-55}
			//	tcp sport vmap { 25:accept, 28:drop }
			//	tcp sport 1024 tcp dport 22
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	case CTokenSequence:
		{
			retExpr.Expr.SetSubType(token)
			//sequence <value>	Sequence number
			//	tcp sequence 22
			//	tcp sequence != 33-45
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	case CTokenMatchTCPAckSeq:
		{
			retExpr.Expr.SetSubType(token)
			//ackseq <value>	Acknowledgement number
			//	tcp ackseq 22
			//	tcp ackseq != 33-45
			//	tcp ackseq { 33, 55, 67, 88 }
			//	tcp ackseq { 33-55 }
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	case CTokenMatchTCPFlags:
		{
			retExpr.Expr.SetSubType(token)
			//flags <flags>	TCP flags
			//	tcp flags { fin, syn, rst, psh, ack, urg, ecn, cwr}
			//	tcp flags cwr
			//	tcp flags != cwr
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
		}
	case CTokenMatchTCPWin:
		{
			retExpr.Expr.SetSubType(token)
			//window <value>	Window
			//	tcp window 22
			//	tcp window != 33-45
			//	tcp window { 33, 55, 67, 88 }
			//	tcp window { 33-55 }
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	case CTokenChecksum:
		{
			retExpr.Expr.SetSubType(token)
			//checksum <checksum>	IP header checksum
			//	tcp checksum 22
			//	tcp checksum != 33-45
			//	tcp checksum { 33, 55, 67, 88 }
			//	tcp checksum { 33-55 }
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
		}
	case CTokenMatchTCPUrgentPtr:
		{
			retExpr.Expr.SetSubType(token)
			//urgptr <pointer>	Urgent pointer
			//	tcp urgptr 22
			//	tcp urgptr != 33-45
			//	tcp urgptr { 33, 55, 67, 88 }
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
		}
	case CTokenMatchTCPDataOffset:
		{
			retExpr.Expr.SetSubType(token)
			//doff <offset>	Data offset
			//	tcp doff 8
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	default:
		{
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	}
	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
