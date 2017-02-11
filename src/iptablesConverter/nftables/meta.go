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
  META STATEMENT
       A meta statement sets the value of a meta expression.  The existing meta fields are: priority, mark, pkttype, nftrace.

       meta {mark | priority | pkttype | nftrace} set value

       A meta statement sets meta data associated with a packet.

       Meta statement types

       ┌─────────┬──────────────────────────────────────────────────────────┬───────────┐
       │Keyword  │ Description                                              │ Value     │
       ├─────────┼──────────────────────────────────────────────────────────┼───────────┤
       │priority │ TC packet priority                                       │ tc_handle │
       ├─────────┼──────────────────────────────────────────────────────────┼───────────┤
       │mark     │ Packet mark                                              │ mark      │
       ├─────────┼──────────────────────────────────────────────────────────┼───────────┤
       │pkttype  │ packet type                                              │ pkt_type  │
       ├─────────┼──────────────────────────────────────────────────────────┼───────────┤
       │nftrace  │ ruleset packet tracing on/off. Use monitor trace command │ 0, 1      │
       │         │ to watch traces                                          │           │
       └─────────┴──────────────────────────────────────────────────────────┴───────────┘

*/
/*
Meta: meta matches packet by metainformation.
meta match
	iifname <input interface name>	Input interface name
		meta iifname "eth0"
		meta iifname != "eth0"
		meta iifname {"eth0", "lo"}
		meta iifname "eth*"
	oifname <output interface name>	Output interface name
		meta oifname "eth0"
		meta oifname != "eth0"
		meta oifname {"eth0", "lo"}
		meta oifname "eth*"
	iif <input interface index>	Input interface index
		meta iif eth0
		meta iif != eth0
	oif <output interface index>	Output interface index
		meta oif lo
		meta oif != lo
		meta oif {eth0, lo}
	iiftype <input interface type>	Input interface type
		meta iiftype {ether, ppp, ipip, ipip6, loopback, sit, ipgre}
		meta iiftype != ether
		meta iiftype ether
	oiftype <output interface type>	Output interface hardware type
		meta oiftype {ether, ppp, ipip, ipip6, loopback, sit, ipgre}
		meta oiftype != ether
		meta oiftype ether
	length <length>	Length of the packet in bytes
		meta length 1000
		meta length != 1000
		meta length > 1000
		meta length 33-45
		meta length != 33-45
		meta length { 33, 55, 67, 88 }
		meta length { 33-55, 67-88 }
	protocol <protocol>	ethertype protocol
		meta protocol ip
		meta protocol != ip
		meta protocol { ip, arp, ip6, vlan }
	nfproto <protocol>
		meta nfproto ipv4
		meta nfproto != ipv6
		meta nfproto { ipv4, ipv6 }
	l4proto <protocol>
		meta l4proto 22
		meta l4proto != 233
		meta l4proto 33-45
		meta l4proto { 33, 55, 67, 88 }
		meta l4proto { 33-55 }
	mark [set] <mark>	Packet mark
		meta mark 0x4
		meta mark 0x00000032
		meta mark and 0x03 == 0x01
		meta mark and 0x03 != 0x01
		meta mark != 0x10
		meta mark or 0x03 == 0x01
		meta mark or 0x03 != 0x01
		meta mark xor 0x03 == 0x01
		meta mark xor 0x03 != 0x01
		meta mark set 0xffffffc8 xor 0x16
		meta mark set 0x16 and 0x16
		meta mark set 0xffffffe9 or 0x16
		meta mark set 0xffffffde and 0x16
		meta mark set 0x32 or 0xfffff
		meta mark set 0xfffe xor 0x16
	skuid <user id>	UID associated with originating socket
		meta skuid {bin, root, daemon}
		meta skuid root
		meta skuid != root
		meta skuid lt 3000
		meta skuid gt 3000
		meta skuid eq 3000
		meta skuid 3001-3005
		meta skuid != 2001-2005
		meta skuid { 2001-2005 }
	skgid <group id>	GID associated with originating socket
		meta skgid {bin, root, daemon}
		meta skgid root
		meta skgid != root
		meta skgid lt 3000
		meta skgid gt 3000
		meta skgid eq 3000
		meta skgid 3001-3005
		meta skgid != 2001-2005
		meta skgid { 2001-2005 }
	rtclassid <class>	Routing realm
		meta rtclassid cosmos
	pkttype <type>	Packet type
		meta pkttype broadcast
		meta pkttype != broadcast
		meta pkttype { broadcast, unicast, multicast}
	cpu <cpu index>	CPU ID
		meta cpu 1
		meta cpu != 1
		meta cpu 1-3
		meta cpu != 1-2
		meta cpu { 2,3 }
		meta cpu { 2-3, 5-7 }
	iifgroup <input group>	Input interface group
		meta iifgroup 0
		meta iifgroup != 0
		meta iifgroup default
		meta iifgroup != default
		meta iifgroup {default}
		meta iifgroup { 11,33 }
		meta iifgroup {11-33}
	oifgroup <group>	Output interface group
		meta oifgroup 0
		meta oifgroup != 0
		meta oifgroup default
		meta oifgroup != default
		meta oifgroup {default}
		meta oifgroup { 11,33 }
		meta oifgroup {11-33}
	cgroup <group>
		meta cgroup 1048577
		meta cgroup != 1048577
		meta cgroup { 1048577, 1048578 }
		meta cgroup 1048577-1048578
		meta cgroup != 1048577-1048578
		meta cgroup {1048577-1048578}

*/
const (
	// Match meta
	CTokenMatchMetaIIfName   TToken = "iifname"
	CTokenMatchMetaOIfName   TToken = "oifname"
	CTokenMatchMetaIIf       TToken = "iif"
	CTokenMatchMetaOIf       TToken = "oif"
	CTokenMatchMetaIIfType   TToken = "iiftype"
	CTokenMatchMetaOIfType   TToken = "oiftype"
	CTokenMatchMetaLength    TToken = "length"
	CTokenMatchMetaProtocol  TToken = "protocol"
	CTokenMatchMetaNfProto   TToken = "nfproto"
	CTokenMatchMetaL4Proto   TToken = "l4proto"
	CTokenMatchMetaMark      TToken = "mark"
	CTokenMatchMetaSkUID     TToken = "skuid"
	CTokenMatchMetaSkGID     TToken = "skgid"
	CTokenMatchMetaRtClassID TToken = "rtclassid"
	CTokenMatchMetaPktType   TToken = "pkttype"
	CTokenMatchMetaCPU       TToken = "cpu"
	CTokenMatchMetaIIfGroup  TToken = "iifgroup"
	CTokenMatchMetaOIfGroup  TToken = "oifgroup"
	CTokenMatchMetaCGroup    TToken = "cgroup"

	CTokenNfProtoIPv4 TToken = "ipv4"
	CTokenNfProtoIPv6 TToken = "ipv6"
)

type TmetaPkttype TToken // pkt_type - Unicast, Broadcast, Multicast
const (
	CPktUnicast   TmetaPkttype = "Unicast"
	CPktBroadcast TmetaPkttype = "Broadcast"
	CPktMulticast TmetaPkttype = "Multicast"
)

type TmetaIfaceindex TToken // iface_index (i.e. eth0, tun0, etc)
type TmetaIfacetype TToken  //uint16    // iface_type 16 bit number
type TmetaUid TID           // uid
type TmetaGid TID           // gid
type TmetaRealm TToken      //[2]uint32        // realm
type TmetaDevgrouptype struct {
	Num     [2]uint32 // devgroup_type
	Default bool
}
type TmetaLength [][2]uint32 // can be single number, or paired min/max
type TmetaProtocol []Tprotocol
type TmetaPriority []Tpriority
type TmetaLayer4Proto []TToken
type TmetaIif []TmetaIfaceindex
type TmetaIifname []TToken
type TmetaIiftype []TmetaIfacetype
type TmetaOif []TmetaIfaceindex
type TmetaOifname []TToken
type TmetaOiftype []TmetaIfacetype
type TmetaIbriport []TToken
type TmetaObriport []TToken
type TmetaCpu [][2]uint32
type TmetaIifgroup []TmetaDevgrouptype
type TmetaOifgroup []TmetaDevgrouptype
type TmetaCgroup [][2]uint32

// meta {length | nfproto | l4proto | protocol | priority}
// [meta] {mark | iif | iifname | iiftype | oif | oifname | oiftype | skuid | skgid | nftrace | rtclassid | ibriport | obriport | pkttype | cpu | iifgroup | oifgroup | cgroup}
type TExpressionMeta struct {
	Expr TChainedExpressions

	//EQ        *TEquate         // i.e. 'iif != {"eth0", lo, "tun0"}'
	//Length    *Tlength       // length		integer (32 bit)	Length of the packet in bytes
	//Protocol  *Tmetaprotocol     // protocol		ether_type			Ethertype protocol value
	//Priority  *Tmetapriority     // priority		integer (32 bit)	TC packet priority
	//Mark      *Tpacketmark     // mark			packetmark			Packet mark
	//Iif       *Tifaceindex   // iif			iface_index			Input interface index
	//Iifname   *Tifaceindex   // iifname		string				Input interface name (i.e. 'iifname != {"eth0", "lo"}'
	//Iiftype   *Tifaceindex   // iiftype		iface_type			Input interface type
	//Oif       *Tifaceindex   // oif			iface_index			Output interface index
	//Oifname   *Tifaceindex   // oifname		string				Output interface name
	//Oiftype   *Tifacetype    // oiftype		iface_type			Output interface hardware type
	//Skuid     *Tuid          // skuid			uid					UID associated with originating socket
	//Skgid     *Tgid          // skgid			gid					GID associated with originating socket
	//Rtclassid *Trealm        // rtclassid		realm				Routing realm
	//Ibriport  *TToken        // ibriport		string				Input bridge interface name
	//Obriport  *TToken        // obriport		string				Output bridge interface name
	//Pkttype   *Tpkttype      // pkttype		pkt_type			packet type
	//Cpu       *TmetaCPU     // cpu			integer (32 bits)	cpu number processing the packet
	//Iifgroup  *Tdevgrouptype // iifgroup		devgroup_type		incoming device group
	//Oifgroup  *Tdevgrouptype // oifgroup		devgroup_type		outgoing device group
	//Cgroup    *TmetaCgroup     // cgroup		integer (32 bits)	control group id
	//Nfproto   *Tnfproto
	//L4Proto   *TLayer4Proto
	//Verdict   *TStatementVerdict
}

func (expr *TExpressionMeta) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TExpressionMeta) GetTokens() []TToken {
	var ret []TToken
	if expr.HasExpression() {
		for _, e := range expr.Expr.Expressions {
			switch tExpr := e.(type) {
			case TmetaIif:
				for _, t := range tExpr {
					ret = append(ret, TToken(t))
				}
			case TmetaOif:
				for _, t := range tExpr {
					ret = append(ret, TToken(t))
				}
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

// meta statements seems to be allowed without the 'meta' keyword
func (rule *TTextStatement) isMetaRule(iTokenIndexRO uint16) bool {
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchMeta {
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}
	return IsMetaRule(tokens[0])
}
func IsMetaRule(token TToken) bool {
	switch token {
	case CTokenMatchMetaIIfName,
		CTokenMatchMetaOIfName,
		CTokenMatchMetaIIf,
		CTokenMatchMetaOIf,
		CTokenMatchMetaIIfType,
		CTokenMatchMetaOIfType,
		CTokenMatchMetaLength,
		CTokenMatchMetaProtocol,
		CTokenMatchMetaNfProto,
		CTokenMatchMetaL4Proto,
		CTokenMatchMetaMark,
		CTokenMatchMetaSkUID,
		CTokenMatchMetaSkGID,
		CTokenMatchMetaRtClassID,
		CTokenMatchMetaPktType,
		CTokenMatchMetaCPU,
		CTokenMatchMetaIIfGroup,
		CTokenMatchMetaOIfGroup,
		CTokenMatchMetaCGroup:
		return true
	}
	if CLogLevel > CLogLevelDebug {
		log.Printf("\tToken='%v' is not part of 'meta'", token)
	}
	return false
}

func (rule *TTextStatement) parseMeta(tokenIndexRO uint16) (*TExpressionMeta, error) {
	caller := ""
	// Caller(1) means the callee of this method (skip 1 stack)
	if _, f, ln, ok := runtime.Caller(1); ok {
		_, fn := filepath.Split(f)
		caller = fmt.Sprintf("%s:%d", fn, ln)
	}

	var retExpr TExpressionMeta
	if rule.isMetaRule(tokenIndexRO) == false {
		log.Panicf("%s: Statement '%+v' is not a match 'meta' based rule!", caller, rule)
	}
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(tokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchMeta {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}
	token := tokens[0] // preserve it for switch statement so we can get next tokens[]
	tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}

	switch token {
	//iifname <input interface name>	Input interface name
	//	meta iifname "eth0"
	//	meta iifname != "eth0"
	//	meta iifname {"eth0", "lo"}
	//	meta iifname "eth*"
	case CTokenMatchMetaIIfName:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := tokens[0].parseCommaSeparated()
			for _, t := range csv {
				retExpr.Expr.Append(TmetaIifname([]TToken{t[0], t[1]}))
				retExpr.Expr.AppendTokens(t[:])
			}
		}
	//oifname <output interface name>	Output interface name
	//	meta oifname "eth0"
	//	meta oifname != "eth0"
	//	meta oifname {"eth0", "lo"}
	//	meta oifname "eth*"
	case CTokenMatchMetaOIfName:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := tokens[0].parseCommaSeparated()
			for _, t := range csv {
				retExpr.Expr.Append(TmetaOifname([]TToken{t[0], t[1]}))
				retExpr.Expr.AppendTokens(t[:])
			}
		}
	//iif <input interface index>	Input interface index
	//	meta iif eth0
	//	meta iif != eth0
	case CTokenMatchMetaIIf:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := tokens[0].parseCommaSeparated()
			for _, t := range csv {
				retExpr.Expr.Append(TmetaIif{TmetaIfaceindex(t[0]), TmetaIfaceindex(t[1])})
				retExpr.Expr.AppendTokens(t[:])
			}
		}
	//oif <output interface index>	Output interface index
	//	meta oif lo
	//	meta oif != lo
	//	meta oif {eth0, lo}
	case CTokenMatchMetaOIf:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := tokens[0].parseCommaSeparated()
			for _, t := range csv {
				retExpr.Expr.Append(TmetaOif{TmetaIfaceindex(t[0]), TmetaIfaceindex(t[1])})
				retExpr.Expr.AppendTokens(t[:])
			}
		}
	//iiftype <input interface type>	Input interface type
	//	meta iiftype {ether, ppp, ipip, ipip6, loopback, sit, ipgre}
	//	meta iiftype != ether
	//	meta iiftype ether
	case CTokenMatchMetaIIfType:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := tokens[0].parseCommaSeparated()
			for _, t := range csv {
				retExpr.Expr.Append(TmetaIiftype{TmetaIfacetype(t[0]), TmetaIfacetype(t[1])})
				retExpr.Expr.AppendTokens(t[:])
			}
		}
	//oiftype <output interface type>	Output interface hardware type
	//	meta oiftype {ether, ppp, ipip, ipip6, loopback, sit, ipgre}
	//	meta oiftype != ether
	//	meta oiftype ether
	case CTokenMatchMetaOIfType:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := tokens[0].parseCommaSeparated()
			for _, t := range csv {
				retExpr.Expr.Append(TmetaOiftype{TmetaIfacetype(t[0]), TmetaIfacetype(t[1])})
				retExpr.Expr.AppendTokens(t[:])
			}
		}
	//length <length>	Length of the packet in bytes
	//	meta length 1000
	//	meta length != 1000
	//	meta length > 1000
	//	meta length 33-45
	//	meta length != 33-45
	//	meta length { 33, 55, 67, 88 }
	//	meta length { 33-55, 67-88 }
	case CTokenMatchMetaLength:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			isNum, nl := tokens[0].tokenToInt() // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
			}
			for _, n := range nl {
				tl := TmetaLength{[2]uint32{uint32(n[0]), uint32(n[1])}}
				retExpr.Expr.Append(tl)
				retExpr.Expr.AppendTokens([]TToken{TToken(strconv.Itoa(n[0])), TToken(strconv.Itoa(n[1]))})
			}
		}
	//protocol <protocol>	ethertype protocol
	//	meta protocol ip
	//	meta protocol != ip
	//	meta protocol { ip, arp, ip6, vlan }
	case CTokenMatchMetaProtocol:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := tokens[0].parseCommaSeparated()
			for _, t := range csv {
				retExpr.Expr.Append(TmetaProtocol{Tprotocol(t[0]), Tprotocol(t[1])})
				retExpr.Expr.AppendTokens(t[:])
			}
		}
	//nfproto <protocol>
	//	meta nfproto ipv4
	//	meta nfproto != ipv6
	//	meta nfproto { ipv4, ipv6 }
	case CTokenMatchMetaNfProto:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := tokens[0].parseCommaSeparated()
			for _, t := range csv {
				retExpr.Expr.Append([2]Tnfproto{Tnfproto(t[0]), Tnfproto(t[1])})
				retExpr.Expr.AppendTokens(t[:])
			}
		}
	//l4proto <protocol>
	//	meta l4proto 22
	//	meta l4proto { 33, 55, 67, 88 }
	//	meta l4proto { 33-55 }
	case CTokenMatchMetaL4Proto:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := tokens[0].parseCommaSeparated()
			for _, t := range csv {
				retExpr.Expr.Append(TmetaLayer4Proto{t[0], t[1]})
				retExpr.Expr.AppendTokens(t[:])
			}
		}
	//mark [set] <mark>	Packet mark
	//	meta mark 0x4
	//	meta mark 0x00000032
	//	meta mark and 0x03 == 0x01
	//	meta mark and 0x03 != 0x01
	//	meta mark != 0x10
	//	meta mark or 0x03 == 0x01
	//	meta mark or 0x03 != 0x01
	//	meta mark xor 0x03 == 0x01
	//	meta mark xor 0x03 != 0x01
	//	meta mark set 0xffffffc8 xor 0x16
	//	meta mark set 0x16 and 0x16
	//	meta mark set 0xffffffe9 or 0x16
	//	meta mark set 0xffffffde and 0x16
	//	meta mark set 0x32 or 0xfffff
	//	meta mark set 0xfffe xor 0x16
	case CTokenMatchMetaMark:
		{
			retExpr.Expr.SetSubType(token)
			startIndex := iTokenIndex - 1 // rewind 1 token
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
				startIndex++
			}
			// grab at most next 4 tokens
			tokens, _, currentRule, err = currentRule.getNextToken(startIndex, 4, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			skip, expr := parseBitwiseMark(tokens)
			retExpr.Expr.Append(expr)
			retExpr.Expr.AppendTokens(tokens[:skip])
			iTokenIndex = startIndex + uint16(skip)
		}
	//skuid <user id>	UID associated with originating socket
	//	meta skuid {bin, root, daemon}
	//	meta skuid root
	//	meta skuid != root
	//	meta skuid lt 3000
	//	meta skuid gt 3000
	//	meta skuid eq 3000
	//	meta skuid 3001-3005
	//	meta skuid != 2001-2005
	//	meta skuid { 2001-2005 }
	case CTokenMatchMetaSkUID:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			// first, try it as number list
			isNum, nl := tokens[0].tokenToInt() // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				// skgid {0, bin, sudo, daemon, usergrp1-usergrp5} - NOTE: ID=0 is root
				tl := tokens[0].parseCommaSeparated()
				for _, t := range tl {
					tu := TmetaUid{IDByName: &[]TToken{t[0], t[1]}}
					retExpr.Expr.Append(tu)
					retExpr.Expr.AppendTokens(t[:])
				}
			} else {
				// can be single, ranged, or comma-separated
				for _, n := range nl {
					tl := TmetaUid{ID: &n}
					retExpr.Expr.Append(tl)
					retExpr.Expr.AppendTokens([]TToken{TToken(strconv.Itoa(n[0])), TToken(strconv.Itoa(n[1]))})
				}
			}
		}
	//skgid <group id>	GID associated with originating socket
	//	meta skgid {bin, root, daemon}
	//	meta skgid root
	//	meta skgid != root
	//	meta skgid lt 3000
	//	meta skgid gt 3000
	//	meta skgid eq 3000
	//	meta skgid 3001-3005
	//	meta skgid != 2001-2005
	//	meta skgid { 2001-2005 }
	case CTokenMatchMetaSkGID:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			// first, try it as number list
			isNum, nl := tokens[0].tokenToInt() // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				// skgid {0, bin, sudo, daemon, usergrp1-usergrp5} - NOTE: ID=0 is root
				tl := tokens[0].parseCommaSeparated()
				for _, t := range tl {
					tg := TmetaGid{IDByName: &[]TToken{t[0], t[1]}}
					retExpr.Expr.Append(tg)
					retExpr.Expr.AppendTokens(t[:])
				}
			} else {
				// can be single, ranged, or comma-separated
				for _, n := range nl {
					tl := TmetaGid{ID: &n}
					retExpr.Expr.Append(tl)
					retExpr.Expr.AppendTokens([]TToken{TToken(strconv.Itoa(n[0])), TToken(strconv.Itoa(n[1]))})
				}
			}
		}
	//rtclassid <class>	Routing realm
	//	meta rtclassid cosmos
	case CTokenMatchMetaRtClassID:
		{
			retExpr.Expr.SetSubType(token)
			retExpr.Expr.Append(TmetaRealm(tokens[0]))
			retExpr.Expr.AppendTokens(tokens)
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
		}
	//pkttype <type>	Packet type
	//	meta pkttype broadcast
	//	meta pkttype != broadcast
	//	meta pkttype { broadcast, unicast, multicast}
	case CTokenMatchMetaPktType:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := tokens[0].parseCommaSeparated()
			for _, t := range csv {
				retExpr.Expr.Append(TmetaPkttype(t[0]))
				retExpr.Expr.AppendTokens(t[:])
			}
		}
	//cpu <cpu index>	CPU ID
	//	meta cpu 1
	//	meta cpu != 1
	//	meta cpu 1-3
	//	meta cpu != 1-2
	//	meta cpu { 2,3 }
	//	meta cpu { 2-3, 5-7 }
	case CTokenMatchMetaCPU:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			isNum, nl := tokens[0].tokenToInt() // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
			}
			retExpr.Expr.AppendToken(CTokenOB)
			for _, n := range nl {
				tl := TmetaCpu{[2]uint32{uint32(n[0]), uint32(n[1])}}
				retExpr.Expr.Append(tl)
				retExpr.Expr.AppendTokens([]TToken{TToken(strconv.Itoa(n[0])), CTokenRange, TToken(strconv.Itoa(n[1])), CTokenCS})
			}
			retExpr.Expr.AppendToken(CTokenCB)
		}
	//iifgroup <input group>	Input interface group
	//	meta iifgroup 0
	//	meta iifgroup != 0
	//	meta iifgroup default
	//	meta iifgroup != default
	//	meta iifgroup {default}
	//	meta iifgroup { 11,33 }
	//	meta iifgroup {11-33}
	case CTokenMatchMetaIIfGroup:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			if tokens[0] == CTokenDefault {
				retExpr.Expr.Append(TmetaDevgrouptype{Default: true})
				retExpr.Expr.AppendTokens(tokens)

				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			} else {
				isNum, nl := tokens[0].tokenToInt() // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
				if isNum == false {
					log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
				}
				for _, n := range nl {
					tl := [2]uint32{uint32(n[0]), uint32(n[1])}
					dg := TmetaDevgrouptype{Num: tl}
					retExpr.Expr.Append(dg)
					retExpr.Expr.AppendTokens([]TToken{TToken(strconv.Itoa(n[0])), TToken(strconv.Itoa(n[1]))})
				}
			}
		}
	//oifgroup <group>	Output interface group
	//	meta oifgroup 0
	//	meta oifgroup != 0
	//	meta oifgroup default
	//	meta oifgroup != default
	//	meta oifgroup {default}
	//	meta oifgroup { 11,33 }
	//	meta oifgroup {11-33}
	case CTokenMatchMetaOIfGroup:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			if tokens[0] == CTokenDefault {
				retExpr.Expr.Append(TmetaDevgrouptype{Default: true})
				retExpr.Expr.AppendTokens(tokens)

				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			} else {
				isNum, nl := tokens[0].tokenToInt() // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
				if isNum == false {
					log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
				}
				for _, n := range nl {
					tl := [2]uint32{uint32(n[0]), uint32(n[1])}
					dg := TmetaDevgrouptype{Num: tl}
					retExpr.Expr.Append(dg)
					retExpr.Expr.AppendTokens([]TToken{TToken(strconv.Itoa(n[0])), TToken(strconv.Itoa(n[1]))})
				}
			}
		}
	//cgroup <group>
	//	meta cgroup 1048577
	//	meta cgroup != 1048577
	//	meta cgroup { 1048577, 1048578 }
	//	meta cgroup 1048577-1048578
	//	meta cgroup != 1048577-1048578
	//	meta cgroup {1048577-1048578}
	case CTokenMatchMetaCGroup:
		{
			retExpr.Expr.SetSubType(token)
			if isEq, e := tokens[0].parseEquates(); isEq {
				retExpr.Expr.Append(&e)
				retExpr.Expr.AppendTokens(tokens)
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			isNum, nl := tokens[0].tokenToInt() // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
			}
			for _, n := range nl {
				tl := [2]uint32{uint32(n[0]), uint32(n[1])}
				retExpr.Expr.Append(tl)
				retExpr.Expr.AppendTokens([]TToken{TToken(strconv.Itoa(n[0])), TToken(strconv.Itoa(n[1]))})
			}
		}
	default:
		{
			log.Panicf("Unhandled 'meta' expression '%s' (in %+v)", tokens, rule)
		}
	} // switch

	// now handle verdicts
	if currentRule != nil {
		var nextErr error
		// get next tokens[] but don't alter iTokenIndex or currentRule because parseX() expects "Next"
		if tokens, _, _, nextErr = currentRule.getNextToken(iTokenIndex, 1, true); nextErr == nil {
			if IsVerdict(tokens[0]) {
				retExpr.Expr.AppendTokens(tokens)
				if v, vErr := currentRule.parseVerdict(iTokenIndex); vErr == nil {
					retExpr.Expr.Append(v)
					if tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true); err != nil {
						err = nil // we're done
					}
				} else {
					log.Panicf("Unhandled Token(%v) encountered - %+v", tokens, currentRule)
				}
			}
		}
	}

	return &retExpr, err
}
