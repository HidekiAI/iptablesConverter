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

// Address families determine the type of packets which are processed. For each address family the kernel contains so called hooks at specific stages of the packet processing paths, which invoke nftables if rules for these hooks exist.
type TAddressFamily string

// All nftables objects exist in address family specific namespaces, therefore all identifiers include an address family. If an identifier is specified without an address family, the ip family is used by default.
const (
	CAddressFamilyIP     TAddressFamily = "ip"
	CAddressFamilyIP6                   = "ip6"
	CAddressFamilyINET                  = "inet"
	CAddressFamilyARP                   = "arp"
	CAddressFamilyBridge                = "bridge"
	CAddressFamilyNetDev                = "netdev"
)

type THookName string

const (
	CHookPrerouting  THookName = "prerouting"
	CHookInput                 = "input"
	CHookForward               = "forward"
	CHookOutput                = "output"
	CHookPostRouting           = "postrouting"
	CHookIngress               = "ingress"
)

type TFamilyHook struct {
}

// IPv4/IPv6/Inet address family hooks

// Tables are containers for chains and sets. They are identified by their address family and their name.
// The address family must be one of ip, ip6, inet, arp, bridge, netdev.  The inet address family is a
// dummy family which is used to create hybrid IPv4/IPv6 tables.  When no address family is specified,
// ip is used by default.
type TTableCommand string

const (
	CTableCommandAdd    TTableCommand = "add"
	CTableCommandDelete               = "delete"
	CTableCommandList                 = "list"
	CTableCommandFlush                = "flush"
)

type TTable struct {
	Family TAddressFamily
	Chains []TChain
}

//Chains are containers for rules. They exist in two kinds, base chains and regular chains.
// A base chain is an entry point for packets from the networking stack, a regular chain
// may be used as jump target and is used for better rule organization.
type TChainCommand string

const (
	CChainCommandAdd    TChainCommand = "add"
	CChainCommandCreate               = "create"
	CChainCommandDelete               = "delete"
	CChainCommandRename               = "rename"
	CChainCommandList                 = "list"
	CChainCommandFlush                = "flush"
)

type TChain struct {
	Rule TRule
}

// Rules are constructed from two kinds of components according to a set of grammatical
// rules: expressions and statements.
type TRuleCommand string

const (
	CRuleCommandAdd    TRuleCommand = "add"
	CRuleCommandInsert              = "insert"
	CRuleCommandDelete              = "delete"
)

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

type Tlength uint32
type Tprotocol string
type Tpriority uint32
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

type Nftables struct {
	X, Y float64
}

func Read(path string) Nftables {
	ret := Nftables{}
	return ret
}
