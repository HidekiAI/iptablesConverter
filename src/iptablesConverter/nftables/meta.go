package nftables

import (
	"log"
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
type Tuid [2]uint32     // uid
type Tgid [2]uint32     // gid
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
	Ibriport  []string        // ibriport		string				Input bridge interface name
	Obriport  []string        // obriport		string				Output bridge interface name
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
func IsMetaRule(rule *TTextStatement) bool {
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchMeta {
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
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
	log.Printf("Token='%v' is not part of meta (in %+v)", tokens, rule)
	return false
}

func parseMeta(rule *TTextStatement) *TExpressionMeta {
	meta := new(TExpressionMeta)
	if IsMetaRule(rule) == false {
		log.Panicf("Statement '%+v' is not a match 'meta' based rule!", rule)
	}
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenMatchMeta {
		meta.Tokens = append(meta.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}
	// setup for next token (special case is when next token is
	// SubStatement - i.e. 'cpu {1, 2-4}' is actual rule.Tokens='cpu {'
	// and rule.SubStatement.Tokens = '1, 2-4', in which len(tokens)==1
	//	if i >= len(tokens) {
	//		// HACK: Until I do it right...
	//		tokens = append(tokens, "") // place a sentinal at end so we do not get outside index reference panic...
	//	}

	switch tokens[0] {
	//iifname <input interface name>	Input interface name
	//	meta iifname "eth0"
	//	meta iifname != "eth0"
	//	meta iifname {"eth0", "lo"}
	//	meta iifname "eth*"
	case CTokenMatchMetaIIfName:
		{
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
				haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if haveToken == false {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			meta.Iifname = append(meta.Iifname, Tifaceindex(tokens[0]))
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken {
				log.Panicf("Unhandled Token(%v) encountered - %+v", tokens, currentRule)
			}
		}
	//oifname <output interface name>	Output interface name
	//	meta oifname "eth0"
	//	meta oifname != "eth0"
	//	meta oifname {"eth0", "lo"}
	//	meta oifname "eth*"
	case CTokenMatchMetaOIfName:
		{
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
				haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if haveToken == false {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			meta.Oifname = append(meta.Oifname, Tifaceindex(tokens[0]))
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken {
				log.Panicf("Unhandled Token(%v) encountered - %+v", tokens, currentRule)
			}
		}
	//iif <input interface index>	Input interface index
	//	meta iif eth0
	//	meta iif != eth0
	case CTokenMatchMetaIIf:
		{
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
				haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if haveToken == false {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			meta.Iif = append(meta.Iif, Tifaceindex(tokens[0]))
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken {
				log.Panicf("Unhandled Token(%v) encountered - %+v", tokens, currentRule)
			}
		}
	//oif <output interface index>	Output interface index
	//	meta oif lo
	//	meta oif != lo
	//	meta oif {eth0, lo}
	case CTokenMatchMetaOIf:
		{
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
				haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if haveToken == false {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			meta.Oif = append(meta.Oif, Tifaceindex(tokens[0]))
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken {
				log.Panicf("Unhandled Token(%v) encountered - %+v", tokens, currentRule)
			}
		}
	//iiftype <input interface type>	Input interface type
	//	meta iiftype {ether, ppp, ipip, ipip6, loopback, sit, ipgre}
	//	meta iiftype != ether
	//	meta iiftype ether
	case CTokenMatchMetaIIfType:
		{
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
				haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if haveToken == false {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			meta.Iiftype = append(meta.Iiftype, Tifaceindex(tokens[0]))
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken {
				log.Panicf("Unhandled Token(%v) encountered - %+v", tokens, currentRule)
			}
		}
	//oiftype <output interface type>	Output interface hardware type
	//	meta oiftype {ether, ppp, ipip, ipip6, loopback, sit, ipgre}
	//	meta oiftype != ether
	//	meta oiftype ether
	case CTokenMatchMetaOIfType:
		{
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
				haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if haveToken == false {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			meta.Oiftype = append(meta.Oiftype, Tifacetype(tokens[0]))
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken {
				log.Panicf("Unhandled Token(%v) encountered - %+v", tokens, currentRule)
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
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
				haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if haveToken == false {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			isNum, nl := tokenToInt(tokens[0])
			if isNum == false {
				log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
			}

			for _, n := range nl {
				tl := Tlength{uint32(n[0]), uint32(n[1])}
				meta.Length = append(meta.Length, tl)
			}
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken {
				log.Panicf("Unhandled Token(%v) encountered - %+v", tokens, currentRule)
			}
		}
	//protocol <protocol>	ethertype protocol
	//	meta protocol ip
	//	meta protocol != ip
	//	meta protocol { ip, arp, ip6, vlan }
	case CTokenMatchMetaProtocol:
		{
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
				haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if haveToken == false {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			meta.Protocol = append(meta.Protocol, Tprotocol(tokens[0]))
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken {
				log.Panicf("Unhandled Token(%v) encountered - %+v", tokens, currentRule)
			}
		}
	//nfproto <protocol>
	//	meta nfproto ipv4
	//	meta nfproto != ipv6
	//	meta nfproto { ipv4, ipv6 }
	case CTokenMatchMetaNfProto:
		{
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
				haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if haveToken == false {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			meta.Nfproto = append(meta.Nfproto, Tnfproto(tokens[0]))
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken {
				log.Panicf("Unhandled Token(%v) encountered - %+v", tokens, currentRule)
			}
		}
	//l4proto <protocol>
	//	meta l4proto 22
	//	meta l4proto != 233
	//	meta l4proto 33-45
	//	meta l4proto { 33, 55, 67, 88 }
	//	meta l4proto { 33-55 }
	case CTokenMatchMetaL4Proto:
		{
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
				haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
				if haveToken == false {
					log.Panicf("Unable to find next token - %+v", rule)
				}
			}
			meta.L4Proto = append(meta.L4Proto, TLayer4Proto(tokens[0]))
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken {
				log.Panicf("Unhandled Token(%v) encountered - %+v", tokens, currentRule)
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
			startIndex := iTokenIndex - 1 // rewind 1 token
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
				startIndex++
			}
			// grab at most next 4 tokens
			haveToken, _, tokens, currentRule = getNextToken(currentRule, startIndex, 4)
			if haveToken == false {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			skip := 0
			skip, meta.Mark = parseBitwiseMark(tokens)
			iTokenIndex = startIndex + uint16(skip)
			haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
			if haveToken {
				log.Panicf("Unhandled Token(%v) encountered - %+v", tokens, currentRule)
			}
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
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
			}
			if len(rule.SubStatement) > 0 {
				// the child is a list of interfaces
				tl := stripRule(rule.SubStatement[0].Tokens)
				for _, t := range tl {
					isNum, nl := tokenToInt(t)
					if isNum == false {
						log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
					}

					for _, n := range nl {
						tl := Tuid{uint32(n[0]), uint32(n[1])}
						meta.Skuid = append(meta.Skuid, tl)
					}
				}
			} else {
				isNum, nl := tokenToInt(tokens[0])
				if isNum == false {
					log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
				}

				for _, n := range nl {
					tl := Tuid{uint32(n[0]), uint32(n[1])}
					meta.Skuid = append(meta.Skuid, tl)
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
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
			}
			if len(rule.SubStatement) > 0 {
				// the child is a list of interfaces
				tl := stripRule(rule.SubStatement[0].Tokens)
				for _, t := range tl {
					isNum, nl := tokenToInt(t)
					if isNum == false {
						log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
					}

					for _, n := range nl {
						tl := Tgid{uint32(n[0]), uint32(n[1])}
						meta.Skgid = append(meta.Skgid, tl)
					}
				}
			} else {
				isNum, nl := tokenToInt(tokens[0])
				if isNum == false {
					log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
				}

				for _, n := range nl {
					tl := Tgid{uint32(n[0]), uint32(n[1])}
					meta.Skgid = append(meta.Skgid, tl)
				}
			}
		}
	//rtclassid <class>	Routing realm
	//	meta rtclassid cosmos
	case CTokenMatchMetaRtClassID:
		{
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
			}
			if len(rule.SubStatement) > 0 {
				// the child is a list of interfaces
				tl := stripRule(rule.SubStatement[0].Tokens)
				for _, t := range tl {
					meta.Rtclassid = append(meta.Rtclassid, Trealm(t))
				}
			} else {
				meta.Rtclassid = append(meta.Rtclassid, Trealm(tokens[0]))
			}
		}
	//pkttype <type>	Packet type
	//	meta pkttype broadcast
	//	meta pkttype != broadcast
	//	meta pkttype { broadcast, unicast, multicast}
	case CTokenMatchMetaPktType:
		{
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
			}
			if len(rule.SubStatement) > 0 {
				// the child is a list of interfaces
				tl := stripRule(rule.SubStatement[0].Tokens)
				for _, t := range tl {
					meta.Pkttype = append(meta.Pkttype, Tpkttype(t))
				}
			} else {
				meta.Pkttype = append(meta.Pkttype, Tpkttype(tokens[0]))
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
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
			}
			if len(rule.SubStatement) > 0 {
				// the child is a list of interfaces
				tl := stripRule(rule.SubStatement[0].Tokens)
				for _, t := range tl {
					isNum, nl := tokenToInt(t)
					if isNum == false {
						log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
					}

					for _, n := range nl {
						tl := [2]uint32{uint32(n[0]), uint32(n[1])}
						meta.Cpu = append(meta.Cpu, tl)
					}
				}
			} else {
				isNum, nl := tokenToInt(tokens[0])
				if isNum == false {
					log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
				}

				for _, n := range nl {
					tl := [2]uint32{uint32(n[0]), uint32(n[1])}
					meta.Cpu = append(meta.Cpu, tl)
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
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
			}
			if len(rule.SubStatement) > 0 {
				// the child is a list of interfaces
				tl := stripRule(rule.SubStatement[0].Tokens)
				for _, t := range tl {
					if t == CTokenDefault {
						meta.Iifgroup = append(meta.Iifgroup, Tdevgrouptype{Default: true})
					} else {
						isNum, nl := tokenToInt(t)
						if isNum == false {
							log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
						}

						for _, n := range nl {
							tl := [2]uint32{uint32(n[0]), uint32(n[1])}
							dg := Tdevgrouptype{Num: tl}
							meta.Iifgroup = append(meta.Iifgroup, dg)
						}
					}
				}
			} else {
				if tokens[0] == CTokenDefault {
					meta.Iifgroup = append(meta.Iifgroup, Tdevgrouptype{Default: true})
				} else {
					isNum, nl := tokenToInt(tokens[0])
					if isNum == false {
						log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
					}

					for _, n := range nl {
						tl := [2]uint32{uint32(n[0]), uint32(n[1])}
						dg := Tdevgrouptype{Num: tl}
						meta.Iifgroup = append(meta.Iifgroup, dg)
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
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
			}
			if len(rule.SubStatement) > 0 {
				// the child is a list of interfaces
				tl := stripRule(rule.SubStatement[0].Tokens)
				for _, t := range tl {
					if t == CTokenDefault {
						meta.Iifgroup = append(meta.Iifgroup, Tdevgrouptype{Default: true})
					} else {
						isNum, nl := tokenToInt(t)
						if isNum == false {
							log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
						}

						for _, n := range nl {
							tl := [2]uint32{uint32(n[0]), uint32(n[1])}
							dg := Tdevgrouptype{Num: tl}
							meta.Oifgroup = append(meta.Oifgroup, dg)
						}
					}
				}
			} else {
				isNum, nl := tokenToInt(tokens[0])
				if isNum == false {
					log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
				}

				for _, n := range nl {
					tl := [2]uint32{uint32(n[0]), uint32(n[1])}
					dg := Tdevgrouptype{Num: tl}
					meta.Oifgroup = append(meta.Oifgroup, dg)
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
			if isEq, e := parseEquates(tokens[0]); isEq {
				meta.EQ = e
			}
			if len(rule.SubStatement) > 0 {
				// the child is a list of interfaces
				tl := stripRule(rule.SubStatement[0].Tokens)
				for _, t := range tl {
					isNum, nl := tokenToInt(t)
					if isNum == false {
						log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
					}

					for _, n := range nl {
						tl := [2]uint32{uint32(n[0]), uint32(n[1])}
						meta.Cgroup = append(meta.Cgroup, tl)
					}
				}
			} else {
				isNum, nl := tokenToInt(tokens[0])
				if isNum == false {
					log.Panicf("Expected numerical token but found '%v' token instead", tokens[0])
				}

				for _, n := range nl {
					tl := [2]uint32{uint32(n[0]), uint32(n[1])}
					meta.Cgroup = append(meta.Cgroup, tl)
				}
			}
		}
	default:
		{
			log.Panicf("Unhandled 'meta' expression '%s' (in %+v)", tokens, rule)
		}
	} // switch

	log.Panicf("'meta' expression '%s' (in %+v) not implemented", tokens, rule)
	return nil
}
