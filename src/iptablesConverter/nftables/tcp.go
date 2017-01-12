package nftables

import (
	"log"
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
	CTokenMatchTCPSeq        TToken = "sequence"
	CTokenMatchTCPAckSeq     TToken = "ackseq"
	CTokenMatchTCPFlags      TToken = "flags"
	CTokenMatchTCPWin        TToken = "window"
	CTokenMatchTCPChksum     TToken = "checksum"
	CTokenMatchTCPUrgentPtr  TToken = "urgptr"
	CTokenMatchTCPDataOffset TToken = "doff"
)

type Ttcpflags uint32 // tcp_flags

// tcp [TCP header field]
type TExpressionHeaderTcp struct {
	Sport    Tinetservice
	Dport    Tinetservice
	Sequence uint32    // sequence number
	Ackseq   uint32    // Acknowledgement number
	Doff     uint8     // 4-bits data offset
	Reserved uint8     // 4-bits reserved area
	Flags    Ttcpflags // tcp_flags
	Window   uint16
	Checksum uint16
	Urgptr   uint16 // Urgetn pointer

	//EQ      TEquate
	//Verdict TStatementVerdict
	Tokens []TToken
}

func parsePayloadTcp(rule *TTextStatement) *TExpressionHeaderTcp {
	retTcp := new(TExpressionHeaderTcp)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchCT {
		retTcp.Tokens = append(retTcp.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	case CTokenMatchTCPDPort:
		{
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	case CTokenMatchTCPSPort:
		{
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	case CTokenMatchTCPSeq:
		{
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	case CTokenMatchTCPAckSeq:
		{
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	case CTokenMatchTCPFlags:
		{
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	case CTokenMatchTCPWin:
		{
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	case CTokenMatchTCPChksum:
		{
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	case CTokenMatchTCPUrgentPtr:
		{
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	case CTokenMatchTCPDataOffset:
		{
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	default:
		{
			log.Panicf("Unhandled token '%s' for 'tcp' (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented: %+v", rule)
	return nil
}
