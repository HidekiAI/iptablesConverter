package nftables

import (
	"log"
	"net"
)

// Set logLevel to:
//	0: no logging
//	1: info
//	2: debug
//	3: verbose debug
const logLevel = 3

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
	CTokenTable   TToken = "table"
	CTokenChain   TToken = "chain"
	CTokenSC      TToken = ";"
	CTokenOB      TToken = "{"
	CTokenCB      TToken = "}"
	CTokenHash    TToken = "#"
	CTokenFS      TToken = `/`
	CTokeneq      TToken = "eq" // i.e. 'meta skgid eq 3000'
	CTokenneq     TToken = "neq"
	CTokenNE      TToken = "!=" // similar to iptable's '!' token i.e. 'meta iif != eth0'
	CTokenEQ      TToken = "==" // i.e. 'meta mark and 0x03 == 0x01'
	CTokenGT      TToken = ">"  // i.e. 'meta length > 1000'
	CTokengt      TToken = "gt" // i.e. 'skuid gt 3000'
	CTokengte     TToken = "gte"
	CTokenGE      TToken = ">="
	CTokenLT      TToken = "<"
	CTokenlt      TToken = "lt" // i.e. 'skgid lt 1000'
	CTokenlte     TToken = "lte"
	CTokenLE      TToken = "<="
	CTokenRange   TToken = "-" // i.e. numerical range 1024-2048
	CTokenCS      TToken = "," // i.e. grouping "http,https,ssh,22-23,domain"
	CTokenSet     TToken = "set"
	CTokenAnd     TToken = "and" // i.e. 'meta mark and 0x03 == 0x01', 'meta mark and 0x03 != 0x01'
	CTokenOr      TToken = "or"  // i.e. 'meta mark set 0xffffffe0 or 0x16', 'ct mark or 0x23 == 0x11'
	CTokenXor     TToken = "xor" // i.e. 'meta mark set 0xfffe xor 0x16'
	CTokenDefault TToken = "default"
	CTokenVMap    TToken = "vmap"

	// Chains
	CTokenType          TToken = "type" //filter, route, nat
	CTokenChecksum      TToken = "checksum"
	CTokenSequence      TToken = "sequence"
	CTokenID            TToken = "id"
	CTokenChainHook     TToken = "hook"
	CTokenChainPriority TToken = "priority"
	CTokenChainPolicy   TToken = "policy"
	CTokenChainDevice   TToken = "device"

	// Statements
	CTokenStatementCT      TToken = "ct"
	CTokenStatementLog     TToken = "log"
	CTokenStatementReject  TToken = "reject"
	CTokenStatementCounter TToken = "counter"
	CTokenStatementMeta    TToken = "meta"
	CTokenStatementLimit   TToken = "limit"
	CTokenStatementSNAT    TToken = "snat"
	CTokenStatementDNAT    TToken = "dnat"
	CTokenStatementQueue   TToken = "queue"
	CTokenStatementIP6Ext  TToken = "ip6ext"

	// Matches (Chain)
	CTokenMatchIP      TToken = "ip"
	CTokenMatchIP6     TToken = "ip6"
	CTokenMatchTCP     TToken = "tcp"
	CTokenMatchUDP     TToken = "udp"
	CTokenMatchUDPLite TToken = "udplite"
	CTokenMatchSCTP    TToken = "sctp"
	CTokenMatchDCCP    TToken = "dccp"
	CTokenMatchAH      TToken = "ah"
	CTokenMatchESP     TToken = "esp"
	CTokenMatchComp    TToken = "comp"
	CTokenMatchICMP    TToken = "icmp"
	CTokenMatchICMPv6  TToken = "icmpv6"
	CTokenMatchEther   TToken = "ether"
	CTokenMatchDST     TToken = "dst"
	CTokenMatchFrag    TToken = "frag"
	CTokenMatchHBH     TToken = "hbh"
	CTokenMatchMH      TToken = "mh"
	CTokenMatchRT      TToken = "rt"
	CTokenMatchVLAN    TToken = "vlan"
	CTokenMatchARP     TToken = "arp"
	CTokenMatchCT      TToken = "ct"
	CTokenMatchMeta    TToken = "meta"
)

type TEquate struct {
	Token TToken
	NE    bool
	GT    bool
	GE    bool
	LT    bool
	LE    bool
}

// Address families determine the type of packets which are processed. For each address family the kernel contains so called hooks at specific stages of the packet processing paths, which invoke nftables if rules for these hooks exist.
type TAddressFamily string

// All nftables objects exist in address family specific namespaces, therefore all identifiers include an address family. If an identifier is specified without an address family, the ip family is used by default.
const (
	CAddressFamilyIP        TAddressFamily = "ip"
	CAddressFamilyIP6       TAddressFamily = "ip6"
	CAddressFamilyINET      TAddressFamily = "inet"
	CAddressFamilyARP       TAddressFamily = "arp"
	CAddressFamilyBridge    TAddressFamily = "bridge"
	CAddressFamilyNetDev    TAddressFamily = "netdev"
	CAddressFamilyUndefined TAddressFamily = ""
)

type THookName string

const (
	// hook refers to an specific stage of the packet while it's being processed through the kernel. More info in Netfilter hooks.
	//	* The hooks for ip, ip6 and inet families are: prerouting, input, forward, output, postrouting.
	//	* The hooks for arp family are: input, output.
	//	* The bridge family handles ethernet packets traversing bridge devices.
	//	* The hook for netdev is: ingress.
	CHookPrerouting  THookName = "prerouting"  // ip, ip6, and inet
	CHookInput       THookName = "input"       // ip, ip6, inet, arp
	CHookForward     THookName = "forward"     // ip, ip6, inet
	CHookOutput      THookName = "output"      // ip, ip6, inet, arp
	CHookPostRouting THookName = "postrouting" // ip, ip6, inet
	CHookIngress     THookName = "ingress"     // netdev
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
	CTableCommandDelete TTableCommand = "delete"
	CTableCommandList   TTableCommand = "list"
	CTableCommandFlush  TTableCommand = "flush"
)

type TTable struct {
	Name   TTableName // i.e. 'nft add table filter', Name=="filter"
	Family TAddressFamily
	// unlike iptables, there are no default chains such as 'INPUT', 'OUTPUT', 'FORWARD', etc
	// Not sure if ChainName is case sensitive, but we'll allow "Input", "INPUT", and "input" to be the same?
	Chains map[TChainName]*TChain // i.e. INPUT, OUTPUT, FORWARD chains
}

//Chains are containers for rules. They exist in two kinds, base chains and regular chains.
// A base chain is an entry point for packets from the networking stack, a regular chain
// may be used as jump target and is used for better rule organization.
type TChainName string
type TChainCommand string
type TChainType string

const (
	CChainCommandAdd    TChainCommand = "add"
	CChainCommandCreate TChainCommand = "create"
	CChainCommandDelete TChainCommand = "delete"
	CChainCommandRename TChainCommand = "rename"
	CChainCommandList   TChainCommand = "list"
	CChainCommandFlush  TChainCommand = "flush"

	// type <type> hook <hook> [device <device>] priority <priority> ; [policy <policy>;]
	// type refers to the kind of chain to be created. Possible types are:
	//	filter: Supported by arp, bridge, ip, ip6 and inet table families.
	//	route: Mark packets (like mangle for the output hook, for other hooks use the type filter instead), supported by ip and ip6.
	//	nat: In order to perform Network Address Translation, supported by ip and ip6.
	CChainTypeFilter TChainType = "filter"
	CChainTypeRoute  TChainType = "route"
	CChainTypeNat    TChainType = "nat"
)

type TChain struct {
	Rule TRule
	Next *TChain // chains are ordered
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
	CRuleCommandInsert  TRuleCommand = "insert"
	CRuleCommandDelete  TRuleCommand = "delete"
	CRuleCommandReplace TRuleCommand = "replace"
)

// Statement is the action performed when the packet match the rule. It could be terminal and non-terminal.
// In a certain rule we can consider several non-terminal statements but only a single terminal statement.
//
// The verdict statement alters control flow in the ruleset and issues policy decisions for packets. The
// valid verdict statements are:
//	* accept: Accept the packet and stop the remain rules evaluation.
//	* drop: Drop the packet and stop the remain rules evaluation.
//	* queue: Queue the packet to userspace and stop the remain rules evaluation.
//	* continue: Continue the ruleset evaluation with the next rule.
//	* return: Return from the current chain and continue at the next rule of the last chain. In a base chain it is equivalent to accept
//	* jump <chain>: Continue at the first rule of <chain>. It will continue at the next rule after a return statement is issued
//	* goto <chain>: Similar to jump, but after the new chain the evaluation will continue at the last chain instead of the one containing the goto statement
type TRuleType struct {
	ChainType TChainType
	Hook      THookName
	Device    string
	Priority  Tpriority
	Policy    TVerdict // type can have default policy

	Tokens []TToken
}
type TRulePayload struct {
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

	Icmp   TICMP
	Icmpv6 TICMPv6
	Dst    TMatchDST
	Frag   TFrag
	Hbh    THbh
	Mh     TMH
	Rt     TRouting
}
type TRuleStatement struct {
	Verdict TStatementVerdict
	Log     TStatementLog
	Reject  TStatementReject
	Counter TStatementCounter
	Meta    TExpressionMeta
	Limit   TStatementLimit
	Nat     TStatementNat
	Queue   TStatementQueue
}
type TRule struct {
	SRule []string // Mainly for debug purpose, each line of rules in a TTable, it is array so it can be tokenized (i.e. differences between "This is a string" as single token versus 4 tokens)

	// type
	Policy TVerdict
	Type   TRuleType

	// Expression
	Meta      TExpressionMeta
	Payload   TRulePayload
	ConnTrack TExpressionConntrack
	Counter   TStatementCounter

	// Statement
	Statement TRuleStatement
}

// The link layer address type is used for link layer addresses. Link layer addresses are specified as a variable amount of groups of two hexadecimal digits separated using colons (:).
//type Tlladdr []uint

// IPAddress structure is same for both IPv6 and IPv4
type TIPAddress struct {
	SAddr  TToken
	IP     net.IP    // IP address without the netmask
	IPNet  net.IPNet // NOTE: net.ParseCIDR() and net.CIDRMask() returns net.IPMask which is []byte
	IsIPv6 bool
}

// Expressions represent values, either constants like network addresses, port numbers etc. or data gathered from the packet during ruleset evaluation. Expressions can be combined using binary, logical, relational and other types of expressions to form complex or relational (match) expressions.  They are also used as arguments to certain types of operations, like NAT, packet marking etc.
// Each expression has a data type, which determines the size, parsing and representation of symbolic values and type compatibility with other expressions.
//type Tifname [16]byte     // ifname - 16-bytes string

type Tpriority int32

const (
	// priority refers to a number used to order the chains or to set them between some Netfilter operations. Possible values are:
	NF_IP_PRI_CONNTRACK_DEFRAG Tpriority = -400
	NF_IP_PRI_RAW              Tpriority = -300
	NF_IP_PRI_SELINUX_FIRST    Tpriority = -225
	NF_IP_PRI_CONNTRACK        Tpriority = -200
	NF_IP_PRI_MANGLE           Tpriority = -150
	NF_IP_PRI_NAT_DST          Tpriority = -100
	NF_IP_PRI_FILTER           Tpriority = 0
	NF_IP_PRI_SECURITY         Tpriority = 50
	NF_IP_PRI_NAT_SRC          Tpriority = 100
	NF_IP_PRI_SELINUX_LAST     Tpriority = 225
	NF_IP_PRI_CONNTRACK_HELPER Tpriority = 300
)

// Shared types amongst other expression/statements
type Tnfproto string
type Tprotocol string
type Tpacketmark struct { // used only by 'meta mark' and 'ct mark'
	// i.e. 'and 0x03 == 0x01', 'set 0xfffe xor 0x16', 'and 0x03 != 0x01', 'set 0xffffffe0 or 0x16'
	// Eg1:
	// 'ct mark and 0x0000ffff == 0x00001234' means
	//	* Use operator 'and' with operand '0x0000ffff' of current packet
	//	* Test result with operator '==' against operand '0x00001234'
	OperatorPacket TToken // CTokenSet, CTokenAnd, CTokenOr, CTokenXor
	OperandPacket  int    // usually hex

	OperatorResult TToken // CTokenEQ, CTokenNE, CTokenOr, CtokenAnd, CTokenXor
	OperandResult  int    // usually hex
}

// Generic type to hold an operand/parameters that can be either numerical (ranged or single), or an alias
type TMinMaxU32 [2]uint32
type TMinMax [2]int
type TMinMaxU16 [2]uint16
type TMinMax16 [2]int16
type TMinMaxU8 [2]uint8
type TMinMax8 [2]int8
type TIntOrAlias struct {
	Num   int
	Alias TToken
	Range TMinMax
}
type TUInt32OrAlias struct {
	Num   uint32
	Alias TToken
	Range TMinMaxU32
}
type TInt8OrAlias struct {
	Num   int8
	Alias TToken
	Range TMinMax8
}
type TUInt8OrAlias struct {
	Num   uint8
	Alias TToken
	Range TMinMaxU8
}
type TInt16OrAlias struct {
	Num   int16
	Alias TToken
	Range TMinMax16
}
type TUInt16OrAlias struct {
	Num   uint16
	Alias TToken
	Range TMinMaxU16
}

type TVerdict string
type TPort uint32

// inet_service
type Tinetservice struct {
	Port        [2]TPort  // i.e. '22' or '8000-8001', for lists like '{22, 80, 443, 8000-8001}', do []Tinetservice
	ServicePort [2]TToken // i.e. 'ssh' or 'ssh-telnet', for lists like '{ssh, http, https, 8000-8001}', do array
}
type Tinetproto struct { // inet_proto
	Range TMinMaxU32 // can be either single number (i.e. {22, -1}) or ranged paired (i.e. {1024-2048})
	Alias TToken     // in some cases it can be a list (i.e. {esp, udp, ah, comp}) - for lists of alias, make sure do to do []Tinetproto
}

// vmap: i.e. 'tcp dport vmap { 22 : accept, 23 : drop }'
type TVMap struct {
	Port        TPort
	ServicePort TToken
	Verdict     TVerdict
}

// ID (i.e. uid or gid) can be either int or string
// i.e. id=bin, root, daemon
// it can also be range based (i.e. '2000-2005')
type TID struct {
	IDByName []TToken // can be CSV (i.e. {bin, root, daemon}
	ID       [2]int   // range based, but if just single, it is {n, -1} - ID=0 is root, -1 indicates unset
}

// Nftables is just a container map of tables where the KEY is a unique
// dotted namespace (family.tableName) for quicker lookup
type TUniqueTableName string // dotted table name such as "ip.filter", "ip6.nat" so that if there are "ip6" and "ip" family to table "filter", we can distinguish it
type Nftables struct {
	Tables map[TUniqueTableName]TTable // key: table name (i.e. "ip.filter", "ip6.filter")
	//sync.RWMutex	// see https://blog.golang.org/go-maps-in-action in terms of concurrency issue with maps
}

func init() {
	log.SetFlags(log.Lshortfile)
}
