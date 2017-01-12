package nftables

// The types and fields comes from 'man 8 nft'
// Conventions:
//	* Txxx - Type declarations
//	* Cxxx - Const variables
// Majority of the variable names are left as-is with the "_" removed (i.e. 'devgroup_type' -> 'Tdevgrouptype')
// though harder to read so that it is easier to port from the man pages.  Possibly in the future, when
// implementations are complete, it may be necessary to refactor for legibility.  But for now, rely
// on 'gocode'/Vim-go and Syntastic (or any other code-completion/intellisense methods) to make your life
// easier...

type TToken string

const (
	CTokenTable TToken = "table"
	CTokenChain        = "chain"
	CTokenSC           = ";"
	CTokenOB           = "{"
	CTokenCB           = "}"
	CTokenHash         = "#"
	CTokenFS           = `/`
)

// Address families determine the type of packets which are processed. For each address family the kernel contains so called hooks at specific stages of the packet processing paths, which invoke nftables if rules for these hooks exist.
type TAddressFamily string

// All nftables objects exist in address family specific namespaces, therefore all identifiers include an address family. If an identifier is specified without an address family, the ip family is used by default.
const (
	CAddressFamilyIP        TAddressFamily = "ip"
	CAddressFamilyIP6                      = "ip6"
	CAddressFamilyINET                     = "inet"
	CAddressFamilyARP                      = "arp"
	CAddressFamilyBridge                   = "bridge"
	CAddressFamilyNetDev                   = "netdev"
	CAddressFamilyUndefined                = ""
)

type THookName string

const (
	// hook refers to an specific stage of the packet while it's being processed through the kernel. More info in Netfilter hooks.
	//	* The hooks for ip, ip6 and inet families are: prerouting, input, forward, output, postrouting.
	//	* The hooks for arp family are: input, output.
	//	* The bridge family handles ethernet packets traversing bridge devices.
	//	* The hook for netdev is: ingress.
	CHookPrerouting  THookName = "prerouting"  // ip, ip6, and inet
	CHookInput                 = "input"       // ip, ip6, inet, arp
	CHookForward               = "forward"     // ip, ip6, inet
	CHookOutput                = "output"      // ip, ip6, inet, arp
	CHookPostRouting           = "postrouting" // ip, ip6, inet
	CHookIngress               = "ingress"     // netdev
)

type TFamilyHook struct {
}

// IPv4/IPv6/Inet address family hooks

// Tables are containers for chains and sets. They are identified by their address family and their name.
// The address family must be one of ip, ip6, inet, arp, bridge, netdev.  The inet address family is a
// dummy family which is used to create hybrid IPv4/IPv6 tables.  When no address family is specified,
// ip is used by default.
type TTableName string
type TTableCommand string

const (
	CTableCommandAdd    TTableCommand = "add"
	CTableCommandDelete               = "delete"
	CTableCommandList                 = "list"
	CTableCommandFlush                = "flush"
)

type TTable struct {
	Name   TTableName // i.e. 'nft add table filter', Name=="filter"
	Family TAddressFamily
	Chains []TChain
}

//Chains are containers for rules. They exist in two kinds, base chains and regular chains.
// A base chain is an entry point for packets from the networking stack, a regular chain
// may be used as jump target and is used for better rule organization.
type TChainName string
type TChainCommand string
type TChainType string

const (
	CChainCommandAdd    TChainCommand = "add"
	CChainCommandCreate               = "create"
	CChainCommandDelete               = "delete"
	CChainCommandRename               = "rename"
	CChainCommandList                 = "list"
	CChainCommandFlush                = "flush"

	// type refers to the kind of chain to be created. Possible types are:
	//	filter: Supported by arp, bridge, ip, ip6 and inet table families.
	//	route: Mark packets (like mangle for the output hook, for other hooks use the type filter instead), supported by ip and ip6.
	//	nat: In order to perform Network Address Translation, supported by ip and ip6.
	CChainTypeFilter TChainType = "filter"
	CChainTypeRoute             = "route"
	CChainTypeNat               = "nat"
)

type TChain struct {
	Name TChainName
	Rule TRule
}

// Rules are constructed from two kinds of components according to a set of grammatical
// rules: expressions and statements.
/*
* handle is an internal number that identifies a certain rule.
* position is an internal number that it's used to insert a rule before a certain handle.
		% nft add rule [<family>] <table> <chain> <matches> <statements>
		% nft insert rule [<family>] <table> <chain> [position <position>] <matches> <statements>
		% nft replace rule [<family>] <table> <chain> [handle <handle>] <matches> <statements>
		% nft delete rule [<family>] <table> <chain> [handle <handle>]
*/
type TRuleCommand string

const (
	CRuleCommandAdd     TRuleCommand = "add"
	CRuleCommandInsert               = "insert"
	CRuleCommandDelete               = "delete"
	CRuleCommandReplace              = "replace"
)

// Statement is the action performed when the packet match the rule. It could be terminal and non-terminal. In a certain rule we can consider several non-terminal statements but only a single terminal statement.
// The verdict statement alters control flow in the ruleset and issues policy decisions for packets. The valid verdict statements are:
//	* accept: Accept the packet and stop the remain rules evaluation.
//	* drop: Drop the packet and stop the remain rules evaluation.
//	* queue: Queue the packet to userspace and stop the remain rules evaluation.
//	* continue: Continue the ruleset evaluation with the next rule.
//	* return: Return from the current chain and continue at the next rule of the last chain. In a base chain it is equivalent to accept
//	* jump <chain>: Continue at the first rule of <chain>. It will continue at the next rule after a return statement is issued
//	* goto <chain>: Similar to jump, but after the new chain the evaluation will continue at the last chain instead of the one containing the goto statement

type TRule struct {
	SRule string // Mainly for debug purpose, each line of rules in a TTable

	// Expression
	Meta    TExpressionMeta
	Payload struct {
		Ether   TExpressionHeaderEther
		Vlan    TExpressionHeaderVlan
		Arp     TExpressionHeaderArp
		Ip      TExpressionHeaderIpv4
		Ip6     TExpressionHeaderIpv6
		Tcp     TExpressionHeaderTcp
		Udp     TExpressionHeaderUdp
		UdpLite TExpressionHeaderUdpLite
		Sctp    TExpressionHeaderSctp
		Dccp    TExpressionHeaderDccp
		Ah      TExpressionHeaderAH
		Esp     TExpressionHeaderESP
		IpComp  TExpressionHeaderIpcomp
		Ip6Ext  TExpressionHeaderIpv6Ext
	}
	ConnTrack TExpressionConntrack

	// Statement
	Statement struct {
		Verdict TStatementVerdict
		Log     TStatementLog
		Reject  TStatementReject
		Counter TStatementCounter
		Meta    TStatementMeta
		Limit   TStatementLimit
		Nat     TStatementNat
		Queue   TStatementQueue
	}
}

type Tbitmask uint
type Tlladdr []uint // The link layer address type is used for link layer addresses. Link layer addresses are specified as a variable amount of groups of two hexadecimal digits separated using colons (:).
type Tipv4addr struct {
	Addr  uint32
	SAddr string // dotted address (i.e. "127.0.0.1") without the mask
}
type Tipv6addr struct {
	Addr  [2]uint64 // 128 bits
	SAddr string    // colon separated address (i.e. "::1", "FE80::") without the mask
}

// Expressions represent values, either constants like network addresses, port numbers etc. or data gathered from the packet during ruleset evaluation. Expressions can be combined using binary, logical, relational and other types of expressions to form complex or relational (match) expressions.  They are also used as arguments to certain types of operations, like NAT, packet marking etc.
// Each expression has a data type, which determines the size, parsing and representation of symbolic values and type compatibility with other expressions.
type Tifaceindex uint32   //iface_index
type Tifname [16]byte     // ifname - 16-bytes string
type Tifacetype uint16    // iface_type 16 bit number
type Tuid uint32          // uid
type Tgid uint32          // gid
type Trealm uint32        // realm
type Tdevgrouptype uint32 // devgroup_type
type Tpkttype string      // pkt_type - Unicast, Broadcast, Multicast
const (
	CPktUnicast   Tpkttype = "Unicast"
	CPktBroadcast          = "Broadcast"
	CPktMulticast          = "Multicast"
)

type Tpriority int32

const (
	// priority refers to a number used to order the chains or to set them between some Netfilter operations. Possible values are:
	NF_IP_PRI_CONNTRACK_DEFRAG Tpriority = -400
	NF_IP_PRI_RAW                        = -300
	NF_IP_PRI_SELINUX_FIRST              = -225
	NF_IP_PRI_CONNTRACK                  = -200
	NF_IP_PRI_MANGLE                     = -150
	NF_IP_PRI_NAT_DST                    = -100
	NF_IP_PRI_FILTER                     = 0
	NF_IP_PRI_SECURITY                   = 50
	NF_IP_PRI_NAT_SRC                    = 100
	NF_IP_PRI_SELINUX_LAST               = 225
	NF_IP_PRI_CONNTRACK_HELPER           = 300
)

type Tlength uint32
type Tprotocol string
type Tpacketmark string

// meta {length | nfproto | l4proto | protocol | priority}
// [meta] {mark | iif | iifname | iiftype | oif | oifname | oiftype | skuid | skgid | nftrace | rtclassid | ibriport | obriport | pkttype | cpu | iifgroup | oifgroup | cgroup}
type TExpressionMeta struct {
	Length    Tlength       // length		integer (32 bit)	Length of the packet in bytes
	Protocol  Tprotocol     // protocol		ether_type			Ethertype protocol value
	Priority  Tpriority     // priority		integer (32 bit)	TC packet priority
	Mark      Tpacketmark   // mark			packetmark			Packet mark
	Iif       Tifaceindex   // iif			iface_index			Input interface index
	Iifname   string        // iifname		string				Input interface name
	Iiftype   Tifaceindex   // iiftype		iface_type			Input interface type
	Oif       Tifaceindex   // oif			iface_index			Output interface index
	Oifname   string        // oifname		string				Output interface name
	Oiftype   Tifacetype    // oiftype		iface_type			Output interface hardware type
	Skuid     Tuid          // skuid		uid					UID associated with originating socket
	Skgid     Tgid          // skgid		gid					GID associated with originating socket
	Rtclassid Trealm        // rtclassid	realm				Routing realm
	Ibriport  string        // ibriport		string				Input bridge interface name
	Obriport  string        // obriport		string				Output bridge interface name
	Pkttype   Tpkttype      // pkttype		pkt_type			packet type
	Cpu       uint32        // cpu			integer (32 bits)	cpu number processing the packet
	Iifgroup  Tdevgrouptype // iifgroup		devgroup_type		incoming device group
	Oifgroup  Tdevgrouptype // oifgroup		devgroup_type		outgoing device group
	Cgroup    uint32        // cgroup		integer (32 bits)	control group id
}

type Tetheraddr string
type Tethertype string

// ether [ethernet header field]
type TExpressionHeaderEther struct {
	Daddr Tetheraddr // daddr	ether_addr	Destination MAC address
	Saddr Tetheraddr // saddr	ether_addr	Source MAC address
	Type  Tethertype // type	ether_type	EtherType
}

// vlan [VLAN header field]
type TExpressionHeaderVlan struct {
	Id   uint16 // vlan id 12-bits
	Cfi  int    // canonical format indicator flag
	Pcp  uint8  // priority code point 3-bits
	Type Tethertype
}

// arp [ARP header field]
type Tarpop string
type TExpressionHeaderArp struct {
	Htype     uint16 // ARP hardware type
	Ptype     Tethertype
	Hlen      uint8
	Plen      uint8
	Operation Tarpop
}

// ip [IPv4 header field]
type Tinetproto string // inet_proto
type TExpressionHeaderIpv4 struct {
	Version   uint8      // IP header version 4-bits
	Hdrlength uint8      // IP header length including options 4-bits
	Dscp      uint8      // Differentiated Services Code Point 6-bits
	Ecn       uint8      // Explicit Congestion Notification 2-bits
	Length    uint16     // Total packet length
	Id        uint16     // IP ID
	FragOff   uint16     // Fragment offset
	Ttl       uint8      // 8-bits
	Protocol  Tinetproto // inet_proto - Upper layer protocol
	Checksum  uint16     // IP header checksum
	Saddr     Tipv4addr  // source address ipv4_addr
	Daddr     Tipv4addr  // Destination address ipv4_addr
}

// ip6 [IPv6 header field]
type TExpressionHeaderIpv6 struct {
	Version   uint8  // IP header version 4-bits
	Priority  string // NOTE: type not documented on man page
	Dscp      uint8  // Differentiated Service Code Point 6-bits
	Ecn       uint8  // Explicit Congestion Notification 2-bits
	Flowlabel uint32 // 20-bits
	Length    uint16 // Payload length
	Nexthdr   Tinetproto
	Hoplimit  uint8
	Saddr     Tipv6addr
	Daddr     Tipv6addr
}

type Tinetservice uint32 // inet_service - ports
type Ttcpflags uint32    // tcp_flags
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
}

// udp [UDP header field]
type TExpressionHeaderUdp struct {
	Sport    Tinetservice
	Dport    Tinetservice
	Length   uint16
	Checksum uint16
}

// udplite [UDP-Lite header field]
type TExpressionHeaderUdpLite struct {
	Sport    Tinetservice
	Dport    Tinetservice
	Cscov    uint16 // Checksum coverage
	Checksum uint16
}

// sctp [SCTP header field]
type TExpressionHeaderSctp struct {
	Sport    Tinetservice
	Dport    Tinetservice
	Vtag     uint32 // Verification tag
	Checksum uint32
}

// dccp [DCCP header field]
type TExpressionHeaderDccp struct {
	Sport Tinetservice
	Dport Tinetservice
}

// ah [AH header field]
type TExpressionHeaderAH struct { // authentication header
	Nexthdr   Tinetservice // Next header protocol
	Hdrlength uint8        // AH Header length
	Reserved  uint8        // Reserved area 4-bits
	Spi       uint32       // Security Parameter Index
	Sequence  uint32       // Sequence number
}

// esp [ESP header field]
type TExpressionHeaderESP struct { // encrypted security payload
	Spi      uint32 // Security Parameter Index
	Sequence uint32 // Sequence number
}

// comp [IPComp header field]
type TExpressionHeaderIpcomp struct {
	Nexthdr Tinetservice // Next header protocol
	Flags   Tbitmask
	Cpi     uint16 // Compression Parameter Index
}

// IPv6 extension header expressions refer to data from an IPv6 packet's extension headers.
type TExpressionHeaderIpv6Ext struct { // IPv6 extension header
}

type Tctstate string
type Tctdir string
type Tctstatus string
type Ttime string
type Tctlabel string
type Tnfproto string

// ct {state | direction | status | mark | expiration | helper | label | bytes | packets} {original | reply | {l3proto | protocol | saddr | daddr | proto-src | proto-dst | bytes | packets}}
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
}

// Statements represent actions to be performed. They can alter control flow (return, jump to a different chain, accept or drop the packet) or can perform actions, such as logging, rejecting a packet, etc.
// Statements exist in two kinds. Terminal statements unconditionally terminate evaluation of the current rule, non-terminal statements either only conditionally or never terminate evaluation of the current rule, in other words,
// they are passive from the ruleset evaluation perspective. There can be an arbitrary amount of non-terminal statements in a rule, but only a single terminal statement as the final statement.
type TVerdict string

const (
	CVerdictAccept   TVerdict = "accept"
	CVerdictDrop              = "drop"
	CVerdictQueue             = "queue"
	CVerdictContinue          = "continue"
	CVerdictReturn            = "return"
	CVerdictJump              = "jump"
	CVerdictGoto              = "goto"
)

// {accept | drop | queue | continue | return}
// {jump | goto} {chain}
type TStatementVerdict struct {
	Verdict TVerdict
	Chain   string // only used by jump | goto
}

// see https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
type TStatementLog struct {
}
type TStatementReject struct {
}
type TStatementCounter struct {
}
type TStatementMeta struct {
}
type TStatementLimit struct {
}
type TStatementNat struct {
}
type TStatementQueue struct {
}

type TUniqueTableName string // dotted table name such as "filter.ip", "nat.ip6" so that if there are "ip6" and "ip" family to table "filter", we can distinguish it
type Nftables struct {
	Tables map[TUniqueTableName]TTable // key: table name (i.e. "filter.ip", "filter.ip6")
}
