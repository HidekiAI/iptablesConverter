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
Ip: ip match
	dscp <value>
		ip dscp cs1
		ip dscp != cs1
		ip dscp 0x38
		ip dscp != 0x20
		ip dscp {cs0, cs1, cs2, cs3, cs4, cs5, cs6, cs7, af11, af12, af13, af21,
		af22, af23, af31, af32, af33, af41, af42, af43, ef}
	length <length>		(Total packet length)
		ip length 232
		ip length != 233
		ip length 333-435
		ip length != 333-453
		ip length { 333, 553, 673, 838}
	id <id>				(IP ID)
		ip id 22
		ip id != 233
		ip id 33-45
		ip id != 33-45
		ip id { 33, 55, 67, 88 }
	frag-off <value>	(Fragmentation offset)
		ip frag-off 222
		ip frag-off != 233
		ip frag-off 33-45
		ip frag-off != 33-45
		ip frag-off { 33, 55, 67, 88 }
	ttl <ttl>	Time to live
		ip ttl 0
		ip ttl 233
		ip ttl 33-55
		ip ttl != 45-50
		ip ttl { 43, 53, 45 }
		ip ttl { 33-55 }
	protocol <protocol>	Upper layer protocol
		ip protocol tcp
		ip protocol 6
		ip protocol != tcp
		ip protocol { icmp, esp, ah, comp, udp, udplite, tcp, dccp, sctp }
	checksum <checksum>	IP header checksum
		ip checksum 13172
		ip checksum 22
		ip checksum != 233
		ip checksum 33-45
		ip checksum != 33-45
		ip checksum { 33, 55, 67, 88 }
		ip checksum { 33-55 }
	saddr <ip source address>	Source address
		ip saddr 192.168.2.0/24
		ip saddr != 192.168.2.0/24
		ip saddr 192.168.3.1 ip daddr 192.168.3.100
		ip saddr != 1.1.1.1
		ip saddr 1.1.1.1
		ip saddr & 0xff == 1
		ip saddr & 0.0.0.255 < 0.0.0.127
	daddr <ip destination address>	Destination address
		ip daddr 192.168.0.1
		ip daddr != 192.168.0.1
		ip daddr 192.168.0.1-192.168.0.250
		ip daddr 10.0.0.0-10.255.255.255
		ip daddr 172.16.0.0-172.31.255.255
		ip daddr 192.168.3.1-192.168.4.250
		ip daddr != 192.168.0.1-192.168.0.250
		ip daddr { 192.168.0.1-192.168.0.250 }
		ip daddr { 192.168.5.1, 192.168.5.2, 192.168.5.3 }
	version <version>	Ip Header version
		ip version 4
	hdrlength <header length>	IP header length
		ip hdrlength 0
		ip hdrlength 15
*/

// ip [IPv4 header field]
type Tipv4Version uint8
type Tipv4HdrLength uint8
type Tipv4Dscp uint8
type Tipv4Ecn uint8
type Tipv4Length uint16
type Tipv4Id uint16
type Tipv4FragOff uint16
type Tipv4TTL uint8
type Tipv4Protocol Tinetproto
type Tipv4Checksum uint16
type Tipv4SAddr []TIPAddress
type Tipv4DAddr []TIPAddress
type TExpressionHeaderIpv4 struct {
	Expr TChainedExpressions

	//Version   *uint8        // IP header version 4-bits
	//Hdrlength *uint8        // IP header length including options 4-bits
	//Dscp      *uint8        // Differentiated Services Code Point 6-bits
	//Ecn       *uint8        // Explicit Congestion Notification 2-bits
	//Length    *uint16       // Total packet length
	//Id        *uint16       // IP ID
	//FragOff   *uint16       // Fragment offset
	//Ttl       *uint8        // 8-bits
	//Protocol  *Tinetproto   // inet_proto - Upper layer protocol
	//Checksum  *uint16       // IP header checksum
	//Saddr     *[]TIPAddress // source address ipv4_addr (can be range-based with '-' or comma separated list)
	//Daddr     *[]TIPAddress // Destination address ipv4_addr
	//EQ        *TEquate
	//Verdict   *TStatementVerdict
	//Counter   *TStatementCounter
}

func (expr *TExpressionHeaderIpv4) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TExpressionHeaderIpv4) GetTokens() []TToken {
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

func (rule *TTextStatement) parsePayloadIp(iTokenIndexRO uint16) (*TExpressionHeaderIpv4, error) {
	var retExpr TExpressionHeaderIpv4
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchIP {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'ip' (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
