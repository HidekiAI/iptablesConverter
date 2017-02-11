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

type Tifaceindex string // iface_index (i.e. eth0, tun0, etc)
type Tifacetype string  //uint16    // iface_type 16 bit number
type Tuid TID           // uid
type Tgid TID           // gid
type Trealm string      //[2]uint32        // realm
type Tdevgrouptype struct {
	Num     [2]uint32 // devgroup_type
	Default bool
}
type Tlength [2]uint32 // can be single number, or paired min/max
type TLayer4Proto string
type Tpkttype string // pkt_type - Unicast, Broadcast, Multicast
const (
	CPktUnicast   Tpkttype = "Unicast"
	CPktBroadcast Tpkttype = "Broadcast"
	CPktMulticast Tpkttype = "Multicast"
)

// meta {length | nfproto | l4proto | protocol | priority}
// [meta] {mark | iif | iifname | iiftype | oif | oifname | oiftype | skuid | skgid | nftrace | rtclassid | ibriport | obriport | pkttype | cpu | iifgroup | oifgroup | cgroup}
type TExpressionMeta struct {
	EQ        TEquate         // i.e. 'iif != {"eth0", lo, "tun0"}'
	Length    []Tlength       // length		integer (32 bit)	Length of the packet in bytes
	Protocol  []Tprotocol     // protocol		ether_type			Ethertype protocol value
	Priority  []Tpriority     // priority		integer (32 bit)	TC packet priority
	Mark      Tpacketmark     // mark			packetmark			Packet mark
	Iif       []Tifaceindex   // iif			iface_index			Input interface index
	Iifname   []Tifaceindex   // iifname		string				Input interface name (i.e. 'iifname != {"eth0", "lo"}'
	Iiftype   []Tifaceindex   // iiftype		iface_type			Input interface type
	Oif       []Tifaceindex   // oif			iface_index			Output interface index
	Oifname   []Tifaceindex   // oifname		string				Output interface name
	Oiftype   []Tifacetype    // oiftype		iface_type			Output interface hardware type
	Skuid     []Tuid          // skuid			uid					UID associated with originating socket
	Skgid     []Tgid          // skgid			gid					GID associated with originating socket
	Rtclassid []Trealm        // rtclassid		realm				Routing realm
	Ibriport  []TToken        // ibriport		string				Input bridge interface name
	Obriport  []TToken        // obriport		string				Output bridge interface name
	Pkttype   []Tpkttype      // pkttype		pkt_type			packet type
	Cpu       [][2]uint32     // cpu			integer (32 bits)	cpu number processing the packet
	Iifgroup  []Tdevgrouptype // iifgroup		devgroup_type		incoming device group
	Oifgroup  []Tdevgrouptype // oifgroup		devgroup_type		outgoing device group
	Cgroup    [][2]uint32     // cgroup		integer (32 bits)	control group id
	Nfproto   []Tnfproto
	L4Proto   []TLayer4Proto
	Verdict   TStatementVerdict
	Tokens    []TToken
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
	if logLevel > 2 {
		log.Printf("\tToken='%v' is not part of 'meta'", token)
	}
	return false
}

func (rule *TTextStatement) parseMeta(tokenIndexRO uint16) (TExpressionMeta, error) {
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
		retExpr.Tokens = append(retExpr.Tokens, tokens[0])
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
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := parseCommaSeparated(tokens[0])
			for _, t := range csv {
				retExpr.Iifname = append(retExpr.Iifname, Tifaceindex(t[0]))
				retExpr.Tokens = append(retExpr.Tokens, t[0])
			}

		}
	//oifname <output interface name>	Output interface name
	//	meta oifname "eth0"
	//	meta oifname != "eth0"
	//	meta oifname {"eth0", "lo"}
	//	meta oifname "eth*"
	case CTokenMatchMetaOIfName:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := parseCommaSeparated(tokens[0])
			for _, t := range csv {
				retExpr.Oifname = append(retExpr.Oifname, Tifaceindex(t[0]))
				retExpr.Tokens = append(retExpr.Tokens, t[0])
			}
		}
	//iif <input interface index>	Input interface index
	//	meta iif eth0
	//	meta iif != eth0
	case CTokenMatchMetaIIf:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := parseCommaSeparated(tokens[0])
			for _, t := range csv {
				retExpr.Iif = append(retExpr.Iif, Tifaceindex(t[0]))
				retExpr.Tokens = append(retExpr.Tokens, t[0])
			}
		}
	//oif <output interface index>	Output interface index
	//	meta oif lo
	//	meta oif != lo
	//	meta oif {eth0, lo}
	case CTokenMatchMetaOIf:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := parseCommaSeparated(tokens[0])
			for _, t := range csv {
				retExpr.Oif = append(retExpr.Oif, Tifaceindex(t[0]))
				retExpr.Tokens = append(retExpr.Tokens, t[0])
			}
		}
	//iiftype <input interface type>	Input interface type
	//	meta iiftype {ether, ppp, ipip, ipip6, loopback, sit, ipgre}
	//	meta iiftype != ether
	//	meta iiftype ether
	case CTokenMatchMetaIIfType:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := parseCommaSeparated(tokens[0])
			for _, t := range csv {
				retExpr.Iiftype = append(retExpr.Iiftype, Tifaceindex(t[0]))
				retExpr.Tokens = append(retExpr.Tokens, t[0])
			}
		}
	//oiftype <output interface type>	Output interface hardware type
	//	meta oiftype {ether, ppp, ipip, ipip6, loopback, sit, ipgre}
	//	meta oiftype != ether
	//	meta oiftype ether
	case CTokenMatchMetaOIfType:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := parseCommaSeparated(tokens[0])
			for _, t := range csv {
				retExpr.Oiftype = append(retExpr.Oiftype, Tifacetype(t[0]))
				retExpr.Tokens = append(retExpr.Tokens, t[0])
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
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			isNum, nl := tokenToInt(tokens[0]) // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
			}
			for _, n := range nl {
				tl := Tlength{uint32(n[0]), uint32(n[1])}
				retExpr.Length = append(retExpr.Length, tl)
				retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[0])))
				if n[1] >= 0 {
					retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[1])))
				}
			}
		}
	//protocol <protocol>	ethertype protocol
	//	meta protocol ip
	//	meta protocol != ip
	//	meta protocol { ip, arp, ip6, vlan }
	case CTokenMatchMetaProtocol:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := parseCommaSeparated(tokens[0])
			for _, t := range csv {
				retExpr.Protocol = append(retExpr.Protocol, Tprotocol(t[0]))
				retExpr.Tokens = append(retExpr.Tokens, t[0])
			}
		}
	//nfproto <protocol>
	//	meta nfproto ipv4
	//	meta nfproto != ipv6
	//	meta nfproto { ipv4, ipv6 }
	case CTokenMatchMetaNfProto:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := parseCommaSeparated(tokens[0])
			for _, t := range csv {
				retExpr.Nfproto = append(retExpr.Nfproto, Tnfproto(t[0]))
				retExpr.Tokens = append(retExpr.Tokens, t[0])
			}
		}
	//l4proto <protocol>
	//	meta l4proto 22
	//	meta l4proto { 33, 55, 67, 88 }
	//	meta l4proto { 33-55 }
	case CTokenMatchMetaL4Proto:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := parseCommaSeparated(tokens[0])
			for _, t := range csv {
				retExpr.L4Proto = append(retExpr.L4Proto, TLayer4Proto(t[0]))
				retExpr.Tokens = append(retExpr.Tokens, t[0])
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
			retExpr.Tokens = append(retExpr.Tokens, token)
			startIndex := iTokenIndex - 1 // rewind 1 token
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
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
			skip := 0
			skip, retExpr.Mark = parseBitwiseMark(tokens)
			retExpr.Tokens = append(retExpr.Tokens, tokens[0:skip]...)
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
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			// first, try it as number list
			if len(retExpr.Skuid) == 0 {
				retExpr.Skuid = []Tuid{Tuid{IDByName: []TToken{}}}
			}
			isNum, nl := tokenToInt(tokens[0]) // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				// skgid {0, bin, sudo, daemon, usergrp1-usergrp5} - NOTE: ID=0 is root
				tl := parseCommaSeparated(tokens[0])
				for _, t := range tl {
					tu := Tuid{IDByName: t[:]}
					retExpr.Skuid = append(retExpr.Skuid, tu)
					retExpr.Tokens = append(retExpr.Tokens, t[:]...)
				}
			} else {
				// can be single, ranged, or comma-separated
				for _, n := range nl {
					tl := Tuid{ID: n}
					retExpr.Skuid = append(retExpr.Skuid, tl)
					retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[0])))
					if n[1] >= 0 {
						retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[1])))
					}
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
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			// first, try it as number list
			if len(retExpr.Skgid) == 0 {
				retExpr.Skgid = []Tgid{Tgid{IDByName: []TToken{}}}
			}
			isNum, nl := tokenToInt(tokens[0]) // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				// skgid {0, bin, sudo, daemon, usergrp1-usergrp5} - NOTE: ID=0 is root
				tl := parseCommaSeparated(tokens[0])
				for _, t := range tl {
					tg := Tgid{IDByName: t[:]}
					retExpr.Skgid = append(retExpr.Skgid, tg)
					retExpr.Tokens = append(retExpr.Tokens, t[:]...)
				}
			} else {
				// can be single, ranged, or comma-separated
				for _, n := range nl {
					tl := Tgid{ID: n}
					retExpr.Skgid = append(retExpr.Skgid, tl)
					retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[0])))
					if n[1] >= 0 {
						retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[1])))
					}
				}
			}
		}
	//rtclassid <class>	Routing realm
	//	meta rtclassid cosmos
	case CTokenMatchMetaRtClassID:
		{
			retExpr.Tokens = append(retExpr.Tokens, token)
			retExpr.Rtclassid = append(retExpr.Rtclassid, Trealm(tokens[0]))
			retExpr.Tokens = append(retExpr.Tokens, tokens[0])
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
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			csv := parseCommaSeparated(tokens[0])
			for _, t := range csv {
				retExpr.Pkttype = append(retExpr.Pkttype, Tpkttype(t[0]))
				retExpr.Tokens = append(retExpr.Tokens, t[0])
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
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			isNum, nl := tokenToInt(tokens[0]) // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
			}
			for _, n := range nl {
				tl := [2]uint32{uint32(n[0]), uint32(n[1])}
				retExpr.Cpu = append(retExpr.Cpu, tl)
				retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[0])))
				if n[1] >= 0 {
					retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[1])))
				}
			}
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
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			if tokens[0] == CTokenDefault {
				retExpr.Iifgroup[0].Default = true
				retExpr.Tokens = append(retExpr.Tokens, tokens...)

				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			} else {
				isNum, nl := tokenToInt(tokens[0]) // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
				if isNum == false {
					log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
				}
				for _, n := range nl {
					tl := [2]uint32{uint32(n[0]), uint32(n[1])}
					dg := Tdevgrouptype{Num: tl}
					retExpr.Iifgroup = append(retExpr.Iifgroup, dg)
					retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[0])))
					if n[1] >= 0 {
						retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[1])))
					}
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
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			if tokens[0] == CTokenDefault {
				retExpr.Oifgroup[0].Default = true
				retExpr.Tokens = append(retExpr.Tokens, tokens...)

				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			} else {
				isNum, nl := tokenToInt(tokens[0]) // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
				if isNum == false {
					log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
				}
				for _, n := range nl {
					tl := [2]uint32{uint32(n[0]), uint32(n[1])}
					dg := Tdevgrouptype{Num: tl}
					retExpr.Oifgroup = append(retExpr.Oifgroup, dg)
					retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[0])))
					if n[1] >= 0 {
						retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[1])))
					}
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
			retExpr.Tokens = append(retExpr.Tokens, token)
			if isEq, e := parseEquates(tokens[0]); isEq {
				retExpr.EQ = e
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
				if err != nil {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			isNum, nl := tokenToInt(tokens[0]) // i.e. '2,3,4-7,8' -> {2,0}, {3,0}, {4,7}, {8,0}
			if isNum == false {
				log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
			}
			for _, n := range nl {
				tl := [2]uint32{uint32(n[0]), uint32(n[1])}
				retExpr.Cgroup = append(retExpr.Cgroup, tl)
				retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[0])))
				if n[1] >= 0 {
					retExpr.Tokens = append(retExpr.Tokens, TToken(strconv.Itoa(n[1])))
				}
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
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				retExpr.Verdict, err = currentRule.parseVerdict(iTokenIndex)
				if tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true); err != nil {
					err = nil // we're done
				}
			} else {
				log.Panicf("Unhandled Token(%v) encountered - %+v", tokens, currentRule)
			}
		}
	}

	return retExpr, err
}
