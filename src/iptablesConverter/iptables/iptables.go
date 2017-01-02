package iptables

import (
	"bufio"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

// Each 'Table' contains a number of built-in and user-defined 'Chains'.
// Each 'Chain' is a list of 'Rules' which can match a set of packets.
// Each 'Rule' specifies what to do with a packet that matches, and jumps to the 'Target'
// 'Target' of built-in type ACCEPT means to let the packet through, DROP means to discard,
// and RETURN means to stop traversing the chain and resume at the next rule where it
// has jumped from.
type ParseError struct {
	Line int
	Msg  string
	Err  error
}

// RuleElement is an unparsed (pre-RuleSpec) sub-sections of Rule, before it gets converted to RuleSpec
type ruleElement struct {
	//processed bool // yet another property for debugging, in which shuld default to false, so that if it remained false, it has not been visited/observed
	// TODO: Currently, RuleElement are read-only type element, thus it's passed as copied reference
	//       instead of pointer.  In the future, if want to enable the 'processed' (bool) flag, have
	//       to work on each methods to be passed as pointer so we can adjust this bool value

	not bool // '!' flag

	// option that are parameterless is assumed to be bool flag
	opcode string // '-' or '--' prefixed arg

	// Params can be empty if option is a bool flag such as '! --remove', it can be CSV, range min:max, integer, comments
	// Note that all the permutations of params are of string type.  The parser will not attempt
	// to guess whether the param are int, string, service port, etc until it is converted to
	// RuleSpec.  This is because it is hard to guess whether it should attempt to convert 'https' to '443'
	// or Hex '10' to decimal 16 (without the '0x' prefix, cannot know if '10' is decimal 10 or 16 hex)
	operand struct {
		sParam     string
		sParamList []string  // used for csv (i.e. "-m multiports --sports ssh,http,https")
		sPaired    [2]string // used like ranges (i.e. "! --sport 1024:2048")
	}
}
type CommandName string

const (
	CommandAppend      CommandName = "--append"       // -A chain ruleSpec
	CommandCheck                   = "--check"        // -C chain ruleSpec
	CommandDelete                  = "--delete"       // -D chain ruleSpec or -D chain runeNum
	CommandInsert                  = "--insert"       // -I chain [rulenum] ruleSpec
	CommandReplace                 = "--replace"      // -R chain ruleNum ruleSpec
	CommandList                    = "--list"         // -L [chain]
	CommandListRules               = "--list-rules"   // -S [chain]
	CommandFlush                   = "--flush"        // -F [chain]
	CommandZero                    = "--zero"         // -Z [chain [ruleNum]]
	CommandNewChain                = "--new-chain"    // -N chain
	CommandDeleteChain             = "--delete-chain" // -X [chain]
	CommandPolicy                  = "--policy"       // -P chain target (i.e. '-P INPUT DROP')
	CommandRenameChain             = "--rename-chain" // -E oldChain newChain
)

// ChainCommand is a raw line of command
type chainCommand struct {
	text string // mainly for debug logging purpose

	command CommandName // i.e. '-A', --append', -I', etc
	chain   ChainName   // i.e. 'INPUT' in append command '-A INPUT', or 'FORWARD' in insert command '-I 30 FORWARD'
}

// TableRow is an unparsed (pre-RuleSpec) rule-specification and chain info in text/string form
type tableRow struct {
	commandArg   chainCommand
	ruleElements []ruleElement

	lineNum int    // mainly for debugging purpose, but useful to make sure rules we are processing is from same line
	strRule string // mainly to preserve rule as-is in case we need it (also useful for debugging and logs)
}

// Table are collection of unparsed TableRows (pre-RuleSpec); series of chains
type tableUnparsed struct {
	isIPv6      bool
	builtinName string // i.e. "*filter", "*nat", "*raw", etc
	lineStart   int    // because map() causes unordered collection, by having min/max
	lineEnd     int    // of line numbers, it will make it easier to iterate for RuleSpec
	rows        []tableRow
}

// AddressFamily type representation
type AddressFamily int

const (
	// IPv4 is default
	IPv4 AddressFamily = iota + 1
	// IPv6 is less common
	IPv6
)

type ChainName string

const (
	// built-in chains
	ChainPREROUTING  ChainName = "PREROUTING"
	ChainINPUT                 = "INPUT"
	ChainFORWARD               = "FORWARD"
	ChainOUTPUT                = "OUTPUT"
	ChainPOSTROUTING           = "POSTROUTING"
)

type TargetName string

const (
	// iptables TARGET
	TargetACCEPT TargetName = "ACCEPT"
	TargetDROP              = "DROP"
	TargetRETURN            = "RETURN"
	// iptables-extensions TARGET
	TargetAUDIT       TargetName = "AUDIT"
	TargetCHECKSUM               = "CHECKSUM"
	TargetCLASSIFY               = "CLASSIFY"
	TargetCLUSTERIPv4            = "CLUSTERIP"
	TargetCONNMARK               = "CONNMARK"
	TargetCONNSECMARK            = "CONNSECMARK"
	TargetCT                     = "CT"
	TargetDNAT                   = "DNAT"
	TargetDNPTv6                 = "DNPT"
	TargetDSCP                   = "DSCP"
	TargetECNv4                  = "ECN"
	TargetHLv6                   = "HL"
	TargetHMARK                  = "HMARK"
	TargetIDLETIMER              = "IDLETIMER"
	TargetLED                    = "LED"
	TargetLOG                    = "LOG"
	TargetMARK                   = "MARK"
	TargetMASQUERADE             = "MASQUERADE"
	TargetMIRRORv4               = "MIRROR"
	TargetNETMAP                 = "NETMAP"
	TargetNFLOG                  = "NFLOG"
	TargetNFQUEUE                = "NFQUEUE"
	TargetNOTRACK                = "NOTRACK"
	TargetRATEEST                = "RATEEST"
	TargetREDIRECT               = "REDIRECT"
	TargetREJECT                 = "REJECT"
	TargetSAMEv4                 = "SAME"
	TargetSECMARK                = "SECMARK"
	TargetSET                    = "SET"
	TargetSNAT                   = "SNAT"
	TargetSNPTv6                 = "SNPT"
	TargetTCPMSS                 = "TCPMSS"
	TargetTCPOPTSTRIP            = "TCPOPTSTRIP"
	TargetTEE                    = "TEE"
	TargetTOS                    = "TOS"
	TargetPROXY                  = "TPROXY"
	TargetTRACE                  = "TRACE"
	TargetTTLv4                  = "TTL"
	TargetULOGv4                 = "ULOG"
)

type Target struct {
	//chainName ChainName  // i.e. INPUT, "FORWARD", "OUTPUT", "USERDEFINEDCHAIN"
	Target TargetName // i.e. "DROP", "ACCEPT", "RETURN", "LOGNDROP", "USERDEFINEDCHAIN"
	Audit  struct {
		AuditType string
	}
	Checksum struct {
		Fill bool
	}
	Classify struct {
		Class [2]int // hex values of major:minor
	}
	Clusteripv4 struct {
		New        bool
		Hashmode   string // Has to be one of sourceip, sourceip-sourceport, sourceip-sourceport-destport.
		Clustermac string // MAC
		TotalNodes int
		LocalNode  int
		HashInit   int // RNG seed
	}
	ConnMark struct {
	}
	ConnSecMark struct {
	}
	Ct struct {
	}
	Dnat      struct{}
	Dnptv6    struct{}
	Dscp      struct{}
	Ecnv4     struct{}
	Hlv6      struct{}
	Hmark     struct{}
	IdleTimer struct{}
	Led       struct{}
	Log       struct {
		LogLevel       string // some distros uses integer, some distros will allow strings of emerg, alert, crit, error, warning, notice, info or debug (decreasing order of priority)
		LogPrefix      string // up to 29 chars
		LogTcpSequence bool
		LogTcpOptions  bool
		LogIpOptions   bool
		LogUID         bool
	}
	Mark       struct{}
	Masquerade struct{}
	Mirrorv4   struct{}
	Netmap     struct{}
	Nflog      struct{}
	Nfqueue    struct{}
	Notrack    struct{}
	RateEst    struct{}
	Redirect   struct{}
	Reject6    struct {
		// IPv6-specific: icmp6-no-route, no-route, icmp6-adm-prohibited, adm-prohibited, icmp6-addr-unreachable, addr-unreach, or icmp6-port-unreachable
		RejectWith string
	}
	Reject4 struct {
		// IPv4-specific: icmp-net-unreachable, icmp-host-unreachable, icmp-port-unreachable, icmp-proto-unreachable, icmp-net-prohibited, icmp-host-prohibited, or icmp-admin-prohibited
		RejectWith string
	}
	Same        struct{}
	SecMark     struct{}
	Set         struct{}
	Snat        struct{}
	Snptv6      struct{}
	TcpMss      struct{}
	TcpOptStrip struct{}
	Tee         struct{}
	Tos         struct{}
	Tproxy      struct{}
	Trace       struct{}
	Ttlv4       struct{}
	Ulogv4      struct{}
}

type Protocol string

const (
	ProtocolTCP     Protocol = "tcp"
	ProtocolUDP              = "udp"
	ProtocolUDPLite          = "udplite"
	ProtocolICMP             = "icmp"
	ProtocolICMPv6           = "icmpv6"
	ProtocolESP              = "esp"
	ProtocolAH               = "ah"
	ProtocolSCTP             = "sctp"
	ProtocolMH               = "mh"
	ProtocolALL              = "all"
)

type Source []string // i.e. '! -s address1/mask,address'
type Destination []string
type Match struct {
	Rule   string            // preserve raw string, used in case where converter cannot handle
	Module string            // i.e. '-m comment'
	Match  RuleSpecExtension // i.e. '-m comment --comment "this is comment"'
}
type NetworkInterface string

// RuleSpec: see man 8 iptables - Note that Target is embedded only when '--jump' is encountered
type RuleSpec struct {
	Rule   string // preserve raw string, used in case where converter cannot handle
	Line   int    // mainly for error purpose
	Result string // again, for debugging purpose to track in the end what was processed and in what order

	//family: i.e. '-4', '--ipv4', '-6', '--ipv6'
	Family AddressFamily
	//protocol: [!] -p, --protocol protocol
	Protocol struct {
		Not bool     // i.e. '! -p tcp'
		P   Protocol // i.e. '-p udp'
	}
	// source: [!] -s, --source address[/mask],[,...]
	Source struct {
		Not bool // i.e. '-s 192.168.42.0/16,192.168.69.0/8', '! -s 127.0.0.1'
		S   Source
	}
	// destination: [!] -d, --destination address[/mask][,...]
	Destination struct {
		Not bool
		D   Destination // i.e. '-d 0.0.0.0/0', '-d ::1/128'
	}
	// match: -m, --match match
	Match Match // i.e. '-m comment --comment "this is comment"'
	// jump: -j, --jump atarget (when '-j RETURN' is encountered, it returns back to the caller, but if it is at the default chain, it is up to what is set at the heading i.e. ':INPUT DROP [0:0]')
	JumpToTarget Target // i.e. '-j ACCEPT', '--jump LOGNDROP', '-j RETURN'
	// goto: -g, --goto chain (when '-j RETURN' is encountered, back to the calling --jump of another chain)
	GotoChain ChainName // i.e. '-g OUTPUT', '--goto USERDEFINEDCHAIN'
	// inInterface: [!] -i, --in-interface name
	InInterface struct {
		Not  bool // i.e. '-i lo', '! -i eth2'
		Name NetworkInterface
	}
	//outInterface: [!] -o, --out-interface name
	OutInterface struct {
		Not  bool
		Name NetworkInterface // i.e. '-o any'
	}
	// fragment: [!] -f, --fragment
	Fragment struct {
		Not bool // i.e. '-f', '! -f'
	}
	// Counters: -c, --set-counters packets, bytes
	Counters struct {
		Packets int
		Bytes   int
	}
}

type AddressType string
type ConnTrackState string
type ConnTrackStatus string
type ConnTrackDir string
type StateState string // subset of "connntrack"

const (
	ATUnspec      AddressType = "UNSPEC"
	ATUnicast                 = "UNICAST"
	ATLocal                   = "LOCAL"
	ATBroadcast               = "BROADCAST"
	ATAnycast                 = "ANYCAST"
	ATMulticast               = "MULTICAST"
	ATBlackhole               = "BLACKHOLE"
	ATUnreachable             = "UNREACHABLE"
	ATProhibit                = "PROHIBIT"
	ATThrow                   = "THROW"
	ATNAT                     = "NAT"
	ATXResolve                = "XRESOLVE"

	CTStateInvalid     ConnTrackState = "INVALID"
	CTStateNew                        = "NEW"
	CTStateEstablished                = "ESTABLISHED"
	CTStateRelated                    = "RELATED"
	CTStateUntracked                  = "UNTRACKED"
	CTStateSNAT                       = "SNAT"
	CTStateDNAT                       = "DNAT"

	CTStatusNone      ConnTrackStatus = "NONE"
	CTStatusExpected                  = "EXPECTED"
	CTStatusSeenReply                 = "SEEN_REPLY"
	CTStatusAssured                   = "ASSURED"
	CTStatusConfirmed                 = "CONFIRMED"

	CTDirOriginal ConnTrackDir = "ORIGINAL"
	CTDirReply                 = "REPLY"

	StateInvalid     StateState = "INVALID"
	StateEstablished            = "ESTABLISHED"
	StateNew                    = "NEW"
	StateRelated                = "RELATED"
	STateUntracked              = "UNTRACKED"
)

// RuleSpecExtension: see man 8 iptables-extensions
type RuleSpecExtension struct {
	// format: '-m name moduleoptions'
	// i.e. '-m comment --comment "this is a comment" -j log'
	Addrtype struct {
		NotSrc        bool
		SrcType       AddressType
		NotDst        bool
		DstType       AddressType
		LimitIfaceIn  bool
		LimitIfaceOut bool
	}
	Ah struct {
		Not bool
		Spi []string
	}
	AhIPv6 struct {
		NotSPI    bool
		Spi       []string
		NotLength bool
		Length    int
		Res       bool
	}
	Bpf struct {
		// i.e. iptables -A OUTPUT -m bpf --bytecode '4,48 0 0 9,21 0 1 6,6 0 0 1,6 0 0 0' -j ACCEPT
		//	4               # number of instructions
		//	48 0 0 9        # load byte  ip->proto
		//	21 0 1 6        # jump equal IPPROTO_TCP
		//	6 0 0 1         # return     pass (non-zero)
		//	6 0 0 0         # return     fail (zero)
		// i.e. iptables -A OUTPUT -m bpf --bytecode "`nfbpf_compile RAW 'ip proto 6'`" -j ACCEPT
		ByteCode string
	}
	Cluster struct {
		TotalNodes       int
		NotLocalNodeMask bool
		LocalNodeMask    int
		HashSeed         int
	}
	Comment struct {
		Comment string
	}
	Connbytes struct {
	}
	Connlabel struct {
	}
	Connlimit struct {
	}
	Connmark struct {
	}
	Conntrack struct {
		NotStateList       bool
		StateList          []ConnTrackState // csv states to match of INVALID|NEW|ESTABLISHED|RELATED|UNTRACKED|SNAT|DNAT
		NotProto           bool
		L4Proto            string // layer-4 protocol to match (by number or name)
		NotOriginalSrc     bool
		OriginalSrc        string // address[/mask]
		NotOriginalDst     bool
		OriginalDst        string
		NotReplySrc        bool
		ReplySrc           string
		NotReplyDst        bool
		ReplyDst           string
		NotOriginalSrcPort bool
		OriginalSrcPort    [2]int // range, i.e. '--ctorigsrcport 1024:2048'
		NotOriginalDstPort bool
		OriginalDstPort    [2]int
		NotReplySrcPort    bool
		ReplySrcPort       [2]int
		NotReplyDstPort    bool
		ReplyDstPort       [2]int
		NotStatusList      bool
		StatusList         []ConnTrackStatus // csv of NONE|EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED
		NotExpire          bool
		Expire             [2]int       // remaining lifetime in seconds
		Dir                ConnTrackDir // either ORIGINAL|REPLY
	}
	Cpu struct {
	}
	Dccp struct {
	}
	Devgroup struct {
	}
	Dscp struct {
	}
	Dst struct {
	}
	Ecn struct {
	}
	Esp struct {
	}
	Eui64IPv6 struct {
	}
	FragIPv6 struct {
	}
	Hashlimit struct {
	}
	HbhIPv6 struct {
	}
	Helper struct {
	}
	HlIPv6 struct {
		// hop limit
		Neq bool
		Eq  int
		Lt  int
		Gt  int
	}
	Icmp struct {
		// Valid ICMP Types:
		//	any
		//	echo-reply (pong)
		//	destination-unreachable
		//		network-unreachable
		//		host-unreachable
		//		protocol-unreachable
		//		port-unreachable
		//		fragmentation-needed
		//		source-route-failed
		//		network-unknown
		//		host-unknown
		//		network-prohibited
		//		host-prohibited
		//		TOS-network-unreachable
		//		TOS-host-unreachable
		//		communication-prohibited
		//		host-precedence-violation
		//		precedence-cutoff
		//	source-quench
		//	redirect
		//		network-redirect
		//		host-redirect
		//		TOS-network-redirect
		//		TOS-host-redirect
		//	echo-request (ping)
		//	router-advertisement
		//	router-solicitation
		//	time-exceeded (ttl-exceeded)
		//		ttl-zero-during-transit
		//		ttl-zero-during-reassembly
		//	parameter-problem
		//		ip-header-bad
		//	required-option-missing
		//	timestamp-request
		//	timestamp-reply
		//	address-mask-request
		//	address-mask-reply
		Not      bool
		IcmpType string // type[/code] | typename (see 'iptables -p icmp -h')
	}
	Icmp6 struct {
		// Valid ICMPv6 Types:
		//	destination-unreachable
		//		no-route
		//		communication-prohibited
		//		address-unreachable
		//		port-unreachable
		//	packet-too-big
		//	time-exceeded (ttl-exceeded)
		//		ttl-zero-during-transit
		//		ttl-zero-during-reassembly
		//	parameter-problem
		//		bad-header
		//		unknown-header-type
		//		unknown-option
		//	echo-request (ping)
		//	echo-reply (pong)
		//	router-solicitation
		//	router-advertisement
		//	neighbour-solicitation (neighbor-solicitation)
		//	neighbour-advertisement (neighbor-advertisement)
		//	redirect
		Not        bool
		Icmpv6Type string // type[/code] | typename (see 'ip6tables -p ipv6-icmp -h')
	}

	Iprange struct {
	}
	Ipv6header struct {
	}
	Ipvs struct {
	}
	Length struct {
	}
	Limit struct {
		Rate  string // i.e. '3/hour'
		Burst int
	}
	Mac struct {
	}
	Mark struct {
	}
	MhIPv6 struct {
	}
	Multiport struct {
		NotSPorts bool
		Sports    []string // i.e. 53,1024:65535 means 53 and range 1024:65535
		NotDPorts bool
		Dports    []string
		NotPorts  bool
		Ports     []string
	}
	Nfacct struct {
	}
	Osf struct {
	}
	Owner struct {
	}
	Physdev struct {
	}
	Pkttype struct {
	}
	Policy struct {
	}
	Quota struct {
	}
	Rateest struct {
	}
	RealmIPv4 struct {
	}
	Recent struct {
	}
	Rpfilter struct {
	}
	RtIPv6 struct {
	}
	Sctp struct {
	}
	Set struct {
	}
	Socket struct {
	}
	State struct {
		NotState  bool
		StateList []StateState
	}
	Statistic struct {
	}
	StringMatch struct {
	}
	Tcp struct {
		NotSPort  bool
		Sport     [2]int // ranged port (i.e. "--sport 1024:2048")
		NotDPort  bool
		Dport     [2]int // ranged
		NotFlags  bool
		FlagsMask []string // csv i.e. 'SYN,ACK,FIN,RST'
		FlagsComp []string // csv what to be set i.e. 'ALL'
		NotSyn    bool
		Syn       bool
		NotOption bool
		Option    int
	}
	Tcpmss struct {
	}
	Time struct {
	}
	Tos struct {
	}
	TtlIPv4 struct {
	}
	U32 struct {
	}
	Udp struct {
		NotSPort bool
		Sport    [2]int
		NotDPort bool
		Dport    [2]int
	}
	UncleanIPv4 struct {
	}
}

// DefaultChainPolicy are commonly pre-defined at header of each tables so that
// if a '-j RETURN' is encountered at the top-most level, it knows which policy
// to fallback to, and commonly added via 'iptables -P INPUT ACCEPT', 'iptables --policy OUTPUT DROP'
// It also contains 'packetCounter:byteCounter' settings but it is ignored (for now)
// since it has no use for parsing and converting to other NF tables usages
type DefaultChainPolicy struct {
	ChainName     ChainName
	Policy        TargetName
	PacketCounter int
	ByteCounter   int
}

// UserDefinedChain are chains that are not built-in
type UserDefinedChain struct {
	Name  TargetName
	Rules []RuleSpec
}

//TableRaw represents the '*raw' table block
// see TABLES section from http://ipset.netfilter.org/iptables.man.html
type TableRaw struct {
	DefaultPolicies   []DefaultChainPolicy
	BuiltInPrerouting []RuleSpec
	BuiltInOutput     []RuleSpec
	Userdefined       []UserDefinedChain
}

//TableNat represents the '*nat' table block
type TableNat struct {
	DefaultPolicies    []DefaultChainPolicy
	BuiltInPrerouting  []RuleSpec
	BuiltInOutput      []RuleSpec
	BuiltInPostrouting []RuleSpec
	Userdefined        []UserDefinedChain
}

//TableMangle represents the '*mangle' table block
type TableMangle struct {
	DefaultPolicies    []DefaultChainPolicy
	BuiltInPrerouting  []RuleSpec
	BuiltInOutput      []RuleSpec
	BuiltInInput       []RuleSpec
	BuiltInForward     []RuleSpec
	BuiltInPostrouting []RuleSpec
	Userdefined        []UserDefinedChain
}

//TableFilter represents the '*filter' table block
type TableFilter struct {
	DefaultPolicies []DefaultChainPolicy
	BuiltInInput    []RuleSpec
	BuiltInForward  []RuleSpec
	BuiltInOutput   []RuleSpec
	Userdefined     []UserDefinedChain
}

//TableSecurity represents the '*security' table block
type TableSecurity struct {
	DefaultPolicies []DefaultChainPolicy
	BuiltInInput    []RuleSpec
	BuiltInOutput   []RuleSpec
	BuiltInForward  []RuleSpec
	Userdefined     []UserDefinedChain
}

//Iptables is a struct representing collections of tables
type Iptables struct {
	Family   AddressFamily
	Raw      TableRaw
	Nat      TableNat
	Mangle   TableMangle
	Filter   TableFilter
	Security TableSecurity
}

// Read the 'iptables.rules' file without validations.  This should/would not
// use libiptc or actual iptables (or ip6tables) command for we cannot/shouldn't assume it
// will be executed on Linux or has libiptc installed (i.e. FreeBSD, OpenBSD, etc).
// Though it can be argued that the tool is to convert existing iptables.rules so
// it should assume it is Linux.
// If the box is on Linux, create a file via 'iptables-save > /tmp/iptables.rules' and
// pass that file down to here (same goes for 'ip6tables-save').
func Read(path string) (Iptables, ParseError) {
	ret := Iptables{}
	err := ParseError{}
	file, openErr := os.Open(path)
	if openErr != nil {
		log.Panic(openErr)
	}
	defer file.Close()

	var filterBlock map[int]string = make(map[int]string, 0)
	var natBlock map[int]string = make(map[int]string, 0)
	var mangleBlock map[int]string = make(map[int]string, 0)
	var rawBlock map[int]string = make(map[int]string, 0)
	var securityBlock map[int]string = make(map[int]string, 0)
	var line string
	currentBlockRef := filterBlock // map is ref type 'map[int]string []'
	ret.Family = IPv4
	scanner := bufio.NewScanner(file)
	lineCount := 1

	// Just collect lines from each blocks, no parsing are done in this for{} loop except to
	// filter out comments that starts with "#" on column 0, also trimmed off white spaces
	// at front and tail of each lines
	for scanner.Scan() {
		line = strings.TrimSpace(scanner.Text())
		if line != "" {

			if ret.Family != IPv6 {
				if isIPv6(line) {
					ret.Family = IPv6
				}
			}

			// ignore # comments
			if strings.HasPrefix(line, "#") == false {
				if strings.HasPrefix(line, "*") == true {
					// Assume it must be a new block
					if strings.Contains(line, "*filter") {
						currentBlockRef = filterBlock
					} else if strings.Contains(line, "*nat") {
						currentBlockRef = natBlock
					} else if strings.Contains(line, "*mangle") {
						currentBlockRef = mangleBlock
					} else if strings.Contains(line, "*raw") {
						currentBlockRef = rawBlock
					} else if strings.Contains(line, "*security") {
						currentBlockRef = securityBlock
					}
				}
				// store line to current block (including lines that starts with ":" and "*"
				// as well as a line which SHOULD end with the "COMMIT"
				currentBlockRef[lineCount] = line
			}
		}
		lineCount++
	}

	// parse each blocks
	ret.Filter, err = parseFilter(filterBlock, ret.Family == IPv6)
	ret.Mangle, err = parseMangle(mangleBlock, ret.Family == IPv6)
	ret.Nat, err = parseNat(natBlock, ret.Family == IPv6)
	ret.Raw, err = parseRaw(rawBlock, ret.Family == IPv6)
	ret.Security, err = parseSecurity(securityBlock, ret.Family == IPv6)

	return ret, err
}

func isIPv6(line string) bool {
	// Hopefully, it was saved direct dump, which contains the string 'ip6tables-save'
	if strings.Contains(line, "ip6tables-save") {
		return true
	}

	// ignore lines that starts with "#" (assumes line has been trimmed of whitespaces)
	if strings.HasPrefix(line, "#") {
		return false
	}

	lc := strings.ToLower(line)

	// we've encountered rules that has something with ipv6 (i.e. "ipv6-icmp"), but just in case it is in '--comment', ignore any lines with comments
	// NOTE: We _ASSUME_ that this rule file is generated via iptables-save/ip6tables-save, which WILL place '--comment' at the end
	// of the line (before the '-j CHAIN'), so we'll just truncate anything after '--comment'
	if strings.Contains(lc, "--comment") {
		// slice based on index
		i := strings.Index(lc, "--comment")
		if i > -1 {
			lc = lc[:i]
		}
	}

	// test for 'ipv6-icmp' or '--icmpv6-type'
	if strings.Contains(lc, "ipv6") {
		return true
	}
	if strings.Contains(lc, "icmpv6") {
		return true
	}
	// test for common indications '::1' or '::1/128' are loopback
	if strings.Contains(lc, "::1") {
		return true
	}
	// test for common indications 'xxxx:xxxx:xxxx::/48', "xxxx:xxxx:xxxx:xxxx::/64", 'fe80::/10', etc
	if strings.Contains(lc, "::/") {
		return true
	}

	return false
}

// format: ":ChainName TargetName [packet:byte]"
func findDefaultPolicies(lines map[int]string) []DefaultChainPolicy {
	var ret []DefaultChainPolicy
	for _, value := range lines {
		if strings.HasPrefix(value, ":") {
			split := strings.Fields(strings.TrimLeft(value, ":"))
			ret = append(ret, DefaultChainPolicy{
				ChainName:     ChainName(split[0]),  // i.e. "INPUT", "FORWARD", "MYCHAIN"
				Policy:        TargetName(split[1]), // i.e. "DROP", "-", "REJECT"
				PacketCounter: 0,
				ByteCounter:   0,
			})
		}
	}
	return ret
}

// Return: bool[0] isNumber,int[1] converted (decimal) value bool[2] isHex
// NOTE: If you are passing a hex value without indication, it's hard to guess
// for example, an HEX value '1000', without the "0x" Prefix, this method will
// have to assume it is 1000 decimal (base 10); even if you prepend with "0"
// so that it is "01000", conversions will think it is decimal 1000!  But
// Because there are cases of '01' (as in paradigm of '0A', '0D', '20'),
// if it is prefixed with "0", we'll assume Hex (but will still treat '20' as decimal!)
// So if you know that you're passing a Hex value (i.e. '20'), just pass it as "0"+"20"
// i.e. isNumber, iBase10, isHex := isNumber("0" + myHexString)
func parseNumber(s string) (bool, int, bool) {
	//containsNumber := strings.ContainsAny(s, "0123456789")
	//containsHex := strings.ContainsAny(s, "0123456789ABCDEFabcdefxX")
	iBase10, err := strconv.Atoi(s) // note: this will treat "020" as integer 20
	isNumber := err == nil

	// if err16 == nil, then it must have been format such as "100D"
	i16, err16 := strconv.ParseInt(s, 16, 32)
	// strconv.ParsInt() recognizes hex-formatted numbers, but to do so, the string _MUST_ start with '0x' (or '0X') and set base==0
	// if err16x == nil, then it must have been format such as "0x100D"
	i16x, err16x := strconv.ParseInt("0x"+s, 0, 32)
	// NOTE: Because a HEX value can start as '0D', we do not assume Octal (00D) and assume Hex (0x0D)
	isHex := err16 == nil || err16x == nil || s[:1] == "0"
	if isHex {
		if err16 == nil {
			// get base10 value
			iBase10 = int(i16)
			isNumber = true
		} else if err16x == nil {
			iBase10 = int(i16x)
			isNumber = true
		}
	}

	return isNumber, iBase10, isHex
}

func lookupServicePort(port string) int {
	//log.Printf("\tLooking up service port '%s'\n", port)
	p, err := strconv.Atoi(port) // Q: Should use parseNumber() here too?
	if err != nil {
		// use net.LookupPort() to see if we get anything
		p, err = net.LookupPort("tcp", port)
		if err != nil {
			p, err = net.LookupPort("udp", port)
			if err != nil {
				log.Panic(err)
			}
		}
	}
	//log.Printf("\t\tService port '%s' -> %d\n", port, p)
	return p
}

func parseQuotedText(strList []string) (string, int) {
	retString := ""
	retCount := 0
	foundClosing := false
	// search for text which begins with "|' and ends with matching punctuations
	//log.Printf("\t\t\tParsing quoted text '%s'\n", strList)
	if strings.HasPrefix(strList[0], "\"") || strings.HasPrefix(strList[0], "'") {
		punctuation := strList[0][:1]
		retString = retString + strList[0] // including the punctuation
		retCount++
		// Check if a single field/word comment has ending quotes on the same word
		if strings.HasSuffix(strList[0], punctuation) {
			foundClosing = true
		} else {
			for _, s := range strList[1:] {
				retCount++
				retString = retString + " " + s
				if strings.HasSuffix(s, punctuation) {
					foundClosing = true
					break
				}
			}
		}

		if foundClosing == false {
			log.Panic("Unable to find closing quote in the string-list passed")
		}
	} else {
		// if no punctuations are found, assume next field is the ONLY string
		retString = strList[0]
		retCount++
	}
	// Could have probably done strings.Join(slice[:retCount], " ") here...
	//log.Printf("\t\t\t> Parsed '%s' (count: %d) from '%s'\n", retString, retCount, strList)
	return retString, retCount
}

// Generate list of RuleElement structs so that parsing can be done
// based on RuleElement.option
// This methid is used to prebuild each rules as a unordered list due to the fact that
// we cannot assume module options will immediately follow in grouped orders.  For example,
// what is expected would seem as follow:
//	'-A INPUT -s 192.168.0.0/16 -d 0/0 -p udp --sport ntp --dport ntp -j ACCEPT'
// but what we may get if it was user/hand edited iptables.rules which may look:
//	'-A INPUT -p udp -s 192.168.0.0/16 -d 0/0 --sport ntp --dport ntp -j ACCEPT'
// where '--sport' and '--dport' comes several fields after the '-p udp' (protocol) module
func makeRuleElementList(rule string) []ruleElement {
	var optionList []ruleElement
	fields := strings.Fields(strings.TrimSpace(rule))
	for i := 0; i < len(fields); i++ {
		//sp := RuleElement{lineNum: line, processed: false}
		sp := ruleElement{}
		field := fields[i]

		if field == "!" {
			sp.not = true
			i++
			field = fields[i]
		}

		if strings.HasPrefix(field, "-") {
			sp.opcode = field
			i++
			field = fields[i]
		}

		if strings.HasPrefix(field, "-") == false {
			qStr, j := parseQuotedText(fields[i:])
			sp.operand.sParam = qStr // whatever it may be, at least preserve it as string
			if (j > 1) || strings.HasPrefix(qStr, "\"") || strings.HasPrefix(qStr, "'") {
				i = i + (j - 1) // because the for{} loop will inc, we don't want to skip one
			} else if j == 1 {
				// could be:
				//	* 22 (number)
				//	* ssh (service port alias)
				//	* 0:1 (minmax number)
				//	* ssh:http (minmax string)
				//	* c,s,v (comma separated)
				//	* http,ssh,https,21,1024:2048,domain (csv and range combination)
				hasComma := strings.Contains(qStr, ",")
				hasColon := strings.Contains(qStr, ":")
				hasByteSeparator := strings.Contains(qStr, "|")
				if hasByteSeparator {
					// special case, commonly used by HEX based i.e. '|C0C1C120C3C4|0A|0D|'
					sp.operand.sParamList = strings.Split(qStr, "|")
				} else if hasComma && hasColon {
					// csv based list that has ranges (i.e. "ssh,ftp,http,https,1024:2048,5353,domain"
					sp.operand.sParamList = strings.Split(qStr, ",")

				} else if hasComma {
					// first, see if any elements are numbers (i.e. [ssh 80 https])
					sp.operand.sParamList = strings.Split(qStr, ",")
				} else if hasColon {
					// range based
					minmax := strings.Split(qStr, ":")
					if len(minmax) == 2 {
						sp.operand.sPaired[0] = minmax[0]
						sp.operand.sPaired[1] = minmax[1]
					} else {
						// it has one or more colon, but it's split to more than 2
						sp.operand.sParamList = minmax
					}
				}
			} else {
				sp.operand.sParam = field // store it as raw field
				log.Panicf("Something wrong with the field '%s', count==0", field)
			}
		}

		// as long as we have an option "--SomeOption" or "-x" we create an element out of it
		// this is because there are some options that are not dependant on parameters (i.e. --remove)
		if sp.opcode != "" {
			optionList = append(optionList, sp)
		}
	}
	return optionList
}

// IN: line containing chain commands (i.e. '-A INPUT -p udp --sport 666 -j ACCEPT')
// OUT: ChainCommand and new string with ChainCommand sliced off
func getChainCommand(s string) (chainCommand, string) {
	slice := strings.Split(strings.TrimSpace(s), " ")
	cc := chainCommand{
		text: strings.Join(slice[0:2], " "), // first 2 element _SHOULD_ indicate command+chainName
	}

	skipIndex := 0
	if slice[0][:1] == "-" {
		// see 'man iptables' in the COMMANDS section
		switch slice[0] {
		case "-A", "--append":
			{
				// -A, --append chain rule-specification
				cc.command = CommandAppend
				cc.chain = ChainName(strings.ToUpper(slice[1])) // it can be user defined such as 'LOGNDROP' rather than built-ins (i.e. INPUT, FORWARD, OUTPUT)
				skipIndex = 2                                   // skip "-A" and ChainName
			}
		case "-I", "--insert":
			{
				// -I, --insert chain [rulenum] rule-specification
				foundRuleNum := false
				// for now, we're not goint to accept '-I' for it gets complicated when it attempts to insert at line outside the range!
				log.Panicf("\tCommand '%s' currently not supported by the parser\n", slice[0])
				skipIndex = 2
				if foundRuleNum {
					// skip also the optional [rulenum]
					skipIndex++
				}
			}
		default:
			{
				log.Panicf("\tCommand '%s' currently not supported by the parser\n", slice[0])
			}
		}
	} else {
		log.Panicf("Expected iptables COMMAND (i.e. '-A', '--append', '-I', etc) but instead, found '%s'\n", slice[0])
	}

	return cc, strings.Join(slice[skipIndex:], " ")
}

// converts each rule line into ordered array of RuleElements
// Assume that each call has already broken down to start of "*name" (i.e. "*filter", "*nat", etc)
// and ended with "COMMIT".  It is assumed to be an error if we encounter more than one
// line which starts with a "*" and "COMMIT"
// a Table consists of series of chains, and each chain usually starts with "-A INPUT", "-A OUTPUT",
// "-A FORWARD", "-A MYUSERDEFINEDCHAIN", etc
func buildTable(tableName string, rules map[int]string, isIPv6 bool) tableUnparsed {
	table := tableUnparsed{
		builtinName: tableName, isIPv6: isIPv6, lineStart: 0, lineEnd: 0,
	}

	for key, value := range rules {
		// we can ignore all lines which starts with ":" (default policies) or "*" (table/chain name)
		if strings.HasPrefix(value, ":") {
			// default policy header
			continue
		} else if strings.HasPrefix(value, "*") {
			// chain/table heading
			table.lineStart = key
			continue
		} else if strings.ToUpper(value) == "COMMIT" {
			table.lineEnd = key
			continue
		}

		// slice away the Chain COMMAND (i.e. '-A INPUT') before we make []RuleElement
		command, ruleWithoutCommand := getChainCommand(value)
		ruleLine := makeRuleElementList(ruleWithoutCommand)
		row := tableRow{commandArg: command, ruleElements: ruleLine, lineNum: key, strRule: value}
		table.rows = append(table.rows, row)
	}

	return table
}

func findOpcode(opcode []string, ruleElementList []ruleElement) (bool, int, ruleElement) {
	//log.Printf("\t\tSearching for opcodes '%s' in '%v'\n", opcode, ruleElementList)
	i := 0
	var re ruleElement
	found := false
	for i, re = range ruleElementList {
		for _, o := range opcode {
			if o == re.opcode {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if found {
		//log.Printf("\t\t\tFound opcode '%s' (%v) at index %d\n", re.opcode, re, i)
	} else {
		log.Fatalf("\n\nUnable to locate opcodes in current rule")
	}
	return found, i, re
}

func parseTargetExtensions(ruleElementList []ruleElement) Target {
	// i.e. 'iptables -A AUDIT_DROP -j AUDIT --type drop'
	found, _, jumpStatement := findOpcode([]string{"-j", "--jump"}, ruleElementList)
	if found == false {
		return Target{}
	}
	// first param is always assumed to be the TARGET (i.e. '-j ACCEPT', '-j MYUSERDEFINEDCHAIN', etc)
	retT := Target{Target: TargetName(strings.ToUpper(jumpStatement.operand.sParam))}

	//log.Printf("\tTARGET: '%s' - %v\n", retT.Target, jumpStatement)
	// find ALL extended options based on TARGET
	done := false
	for _, s := range ruleElementList {
		if done {
			break
		}
		switch retT.Target {
		// default targets: ACCEPT, DROP, and RETURN
		case TargetACCEPT:
			{
				// do nothing, there are no extended options
				done = true // opt out of the for{} loop
				break
			}
		case TargetDROP:
			{
				// do nothing, there are no extended options
				done = true // opt out of the for{} loop
				break
			}
		case TargetRETURN:
			{
				// do nothing, there are no extended options
				done = true // opt out of the for{} loop
				break
			}
			// extension TARGETs
		case TargetAUDIT:
			{
				switch s.opcode {
				case "--type":
					{
						// --type {accept|drop|reject}
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case TargetCHECKSUM:
			{
				switch s.opcode {
				case "--checksum-fill":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case TargetCLASSIFY:
			{
				switch s.opcode {
				case "--set-class":
					{
						// --set-class major:minor
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case TargetCLUSTERIPv4:
			{
				switch s.opcode {
				case "--new":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--hasmode":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--clustermac":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--toal-nodes":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--local-node":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--hash-init":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetCONNMARK:
			{
				switch s.opcode {
				case "--set-xmark":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--save-mark":
					{
						// --save-mark [--nfmask nfmask] [--ctmask ctmask] or if --set-xmark enabled, --save-mark [--mask mask]
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--restore-mark":
					{
						// --restore-mark [--nfmask nfmask] [--ctmask ctmask] or if --set-xmark enabled, --restore-mark [--mask mask]
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--and-mark":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--or-mark":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--xor-mark":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--set-mark":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetCONNSECMARK:
			{
				switch s.opcode {
				case "--save":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--restore":
					{
						//
					}
					log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
				}
			}
		case TargetCT:
			{
				switch s.opcode {
				case "--notrack":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--helper":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--ctevents":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--expevents":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--zone":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--timeout":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetDNAT:
			{
				switch s.opcode {
				case "--to-destination":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--random":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--persistent":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetDNPTv6:
			{
				switch s.opcode {
				case "--src-pfx":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--dst-pfx":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetDSCP:
			{
				switch s.opcode {
				case "--set-dscp":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--set-dscp-class":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetECNv4:
			{
				switch s.opcode {
				case "--ecn-tcp-remove":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case TargetHLv6:
			{
				switch s.opcode {
				case "--hl-set":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--hl-dec":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--hl-inc":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetHMARK:
			{
				switch s.opcode {
				case "--hmark-tuple":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--hmark-mod":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--hmark-offset":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--hmark-src-prefix":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--hmark-dst-prefix":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--hmark-sport-mask":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--hark-dport-mask":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--hmark-spi-mask":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--hmark-proto-mask":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--hmark-rnd":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetIDLETIMER:
			{
				switch s.opcode {
				case "--timeout":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--label":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetLED:
			{
				switch s.opcode {
				case "--led-trigger-id":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--led-delay":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--led-always-blink":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetLOG:
			{
				switch s.opcode {
				case "--log-level":
					{
						// --log-level level : level can be numeric or mnemonic
						retT.Log.LogLevel = s.operand.sParam
					}
				case "--log-prefix":
					{
						// --log-prefix prefix
						retT.Log.LogPrefix = s.operand.sParam
					}
				case "--log-tcp-sequence":
					{
						retT.Log.LogTcpSequence = true
					}
				case "--log-tcp-options":
					{
						retT.Log.LogTcpOptions = true
					}
				case "--log-uid":
					{
						retT.Log.LogUID = true
					}
				}
			}
		case TargetMARK:
			{
				switch s.opcode {
				case "--set-xmark":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--set-mark":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--and-mark":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--or-mark":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--xor-mark":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetMASQUERADE:
			{
				switch s.opcode {
				case "--to-ports":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--random":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetMIRRORv4:
			{
				// do nothing, there are no extended options
				done = true // opt out of the for{} loop
				break
			}
		case TargetNETMAP:
			{
				switch s.opcode {
				case "--to":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case TargetNFLOG:
			{
				switch s.opcode {
				case "--nflog-group":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--nflog-prefix":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--nflog-range":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--nflog-threshold":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetNFQUEUE:
			{
				switch s.opcode {
				case "--queue-num":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--queue-balance":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--queue-bypass":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--queue-cpu-fanout":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetNOTRACK:
			{
				// do nothing, there are no extended options
				done = true // opt out of the for{} loop
				break
			}
		case TargetRATEEST:
			{
				switch s.opcode {
				case "--rateest-name":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--rateest-interval":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--rateest-ewmalog":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetREDIRECT:
			{
				switch s.opcode {
				case "--to-ports":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--random":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetREJECT:
			{
				// there are IPv4 and IPv6 differences, all the IPv4 starts with "icmp-" while IPv6 has ones like 'adm-' and 'addr-'
				switch s.opcode {
				case "--reject-with":
					{
						//
						if strings.HasPrefix(s.operand.sParam, "icmp-") {
							retT.Reject4.RejectWith = s.operand.sParam
						} else {
							retT.Reject6.RejectWith = s.operand.sParam
						}
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
				// Q: Can '-j REJECT --reject-with t1 --reject-with t2' pattern occur, or can it only have one?
			}
		case TargetSAMEv4:
			{
				switch s.opcode {
				case "--to":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--nodst":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--random":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetSECMARK:
			{
				switch s.opcode {
				case "--selctx":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case TargetSET:
			{
				switch s.opcode {
				case "--add-set":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--del-set":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--timeout":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--exist":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetSNAT:
			{
				switch s.opcode {
				case "--to-source":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--random":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--persistent":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetSNPTv6:
			{
				switch s.opcode {
				case "--src-pfx":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--dst-pfx":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetTCPMSS:
			{
				switch s.opcode {
				case "--set-mss":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--clam-mss-to-pmtu":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetTCPOPTSTRIP:
			{
				switch s.opcode {
				case "--strip-options":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case TargetTEE:
			{
				switch s.opcode {
				case "--gateway":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case TargetTOS:
			{
				switch s.opcode {
				case "--set-tos":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--and-tos":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--or-tos":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--xor-tos":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetPROXY:
			{
				switch s.opcode {
				case "--on-port":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--on-ip":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "tproxy-mark":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetTRACE:
			{
				// do nothing, there are no extended options
				done = true // opt out of the for{} loop
				break
			}
		case TargetTTLv4:
			{
				switch s.opcode {
				case "--ttl-set":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--ttl-dec":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--ttl-inc":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		case TargetULOGv4:
			{
				switch s.opcode {
				case "--ulog-nlgroup":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--ulog-prefix":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--ulog-cprange":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				case "--ulog-qthreshold":
					{
						//
						log.Panicf("CODE ME! - '%s' with option '%s' currently unsupported", retT.Target, s.opcode)
					}
				}
			}
		default:
			{
				// if here, assume it is a user defined target (i.e. "LOGNDROP"), which shouldn't have any options
				done = true // opt out of the for{} loop
				break
			}
		}
	}
	return retT
}

func parseRuleSpec(row tableRow, isIPv6 bool) (RuleSpec, ParseError) {
	//log.Printf("%d: === Begin parseRuleSpec(%s)\n\tChainCommand: %v\n\tRow element count: %d\n\tElements: %v\n",
	//	row.lineNum,
	//	row.strRule,
	//	row.commandArg.text,
	//	len(row.ruleElements),
	//	row.ruleElements)

	retRule := RuleSpec{
		Line:   row.lineNum,
		Rule:   row.strRule,
		Result: row.commandArg.text,
	}
	parseErr := ParseError{}
	for _, ruleElement := range row.ruleElements {
		//log.Printf("%d:\tParsing Rule '%s' of %v\n", row.lineNum, ruleElement.opcode, ruleElement)
		handled := false
		additionalLog := ""

		switch ruleElement.opcode {
		case "-4", "--ipv4":
			{
				retRule.Family = IPv4
				if isIPv6 {
					parseErr.Line = row.lineNum
					parseErr.Msg = "Parse requested as IPv6, but found '--ipv4' in rules"
					log.Panic(parseErr)
				}
				handled = true
			}
		case "-6", "--ipv6":
			{
				retRule.Family = IPv6
				if isIPv6 == false {
					parseErr.Line = row.lineNum
					parseErr.Msg = "Parse requested as IPv4, but found '--ipv6' in rules"
					log.Panic(parseErr)
				}
				handled = true
			}
		case "-p", "--protocol":
			{
				retRule.Protocol.Not = ruleElement.not
				retRule.Protocol.P = Protocol(ruleElement.operand.sParam)
				handled = true
			}
		case "-s", "--source":
			{
				retRule.Source.Not = ruleElement.not
				retRule.Source.S = Source(ruleElement.operand.sParamList)
				handled = true
			}
		case "-d", "--destination":
			{
				retRule.Destination.Not = ruleElement.not
				retRule.Destination.D = Destination(ruleElement.operand.sParamList)
				handled = true
			}
		case "-m", "--match":
			{
				//log.Printf("%d:\t\tMatch '%s'\n", row.lineNum, ruleElement.operand.sParam)
				retRule.Match, parseErr = parseMatch(ruleElement, row, isIPv6)
				if parseErr.Msg != "" {
					log.Panicf("%d: Failed to parse match '%s'\n", row.lineNum, ruleElement.operand.sParam)
					log.Panic(parseErr)
				}
				additionalLog = retRule.Match.Rule
				handled = true
			}
		case "-j", "--jump":
			{
				// parse target-extensions (i.e. AUDIT, CHECKSUM, LOG, etc)
				// i.e. '-j LOG --log-level 7 --log-prefix "Denied: "
				// Special case: '--jump RETURN', if "RETURN" is at the top of the
				// chain (built-in chain), it is up to the default policy defined
				// at headings of each tables
				retRule.JumpToTarget = parseTargetExtensions(row.ruleElements)
				handled = true
			}
		case "-g", "--goto":
			{
				retRule.GotoChain = ChainName(ruleElement.operand.sParam)
				handled = true
			}
		case "-i", "--in-interface":
			{
				retRule.InInterface.Not = ruleElement.not
				retRule.InInterface.Name = NetworkInterface(ruleElement.operand.sParam)
				handled = true
			}
		case "-o", "--out-interface":
			{
				retRule.OutInterface.Not = ruleElement.not
				retRule.OutInterface.Name = NetworkInterface(ruleElement.operand.sParam)
				handled = true
			}
		case "-f", "--fragment":
			{
				log.Panic("-f/--fragment currently unsupported")
				handled = true
			}
		case "-c", "--set-counters":
			{
				isNumber, n, _ := parseNumber(ruleElement.operand.sPaired[0])
				if isNumber {
					retRule.Counters.Packets = n
				}
				isNumber, n, _ = parseNumber(ruleElement.operand.sPaired[1])
				if isNumber {
					retRule.Counters.Bytes = n
				}
				handled = true
			}
		}

		if handled {
			if additionalLog != "" {
				retRule.Result += " " + additionalLog
			} else {
				retRule.Result += " " + ruleElement.opcode + " " + ruleElement.operand.sParam
			}
		}
	}
	log.Printf("%d: '%s'\n\tParse Error: %v\n", row.lineNum, retRule.Result, parseErr)
	return retRule, parseErr
}

func printDebugNot(not bool) string {
	if not {
		return "!"
	}
	return ""
}

func parseMatch(matchModule ruleElement, row tableRow, isIPv6 bool) (Match, ParseError) {
	retMatch := Match{
		Rule:   matchModule.opcode + " " + matchModule.operand.sParam, // keep appending to this string as we find options
		Module: matchModule.operand.sParam,                            // i.e. "-m udp", '--match comment --comment "this is a comment"'
	}
	parseErr := ParseError{}
	//log.Printf("%d:\t\t\tSearching match options for: '%s'\n", row.lineNum, retMatch.rule)
	done := false
	hasOption := false
	for _, ruleElement := range row.ruleElements {
		if done {
			break
		}
		// all options either starts with '!' (i.e. '! --src-type LOCAL' or '--' (i.e. '--comment').
		// anything else (i.e. starts with '-' (single minus), etc are considered to be not based
		// on iptables-extensions type and signals as end of match
		//log.Printf("%d:\t\t\t\tMatch %d: '%s'\n", row.lineNum, ei, ruleElement.opcode)

		// ALL options for the '--match' module starts with '--' (no short hand of '-')
		handled := false
		switch matchModule.operand.sParam {
		case "addrtype":
			{
				switch ruleElement.opcode {
				case "--src-type":
					{
						retMatch.Match.Addrtype.NotSrc = ruleElement.not
						retMatch.Match.Addrtype.SrcType = AddressType(ruleElement.operand.sParam)

						hasOption = true
						handled = true
					}
				case "--dst-type":
					{
						retMatch.Match.Addrtype.NotDst = ruleElement.not
						retMatch.Match.Addrtype.DstType = AddressType(ruleElement.operand.sParam)

						hasOption = true
						handled = true
					}
				case "--limit-iface-in":
					{
						retMatch.Match.Addrtype.LimitIfaceIn = true

						hasOption = true
						handled = true
					}
				case "--limit-iface-out":
					{
						retMatch.Match.Addrtype.LimitIfaceOut = true

						hasOption = true
						handled = true
					}
				}
			}
		case "ah":
			{
				switch ruleElement.opcode {
				case "--ahspi":
					{
						if isIPv6 {
							retMatch.Match.AhIPv6.NotSPI = ruleElement.not
							retMatch.Match.AhIPv6.Spi = strings.Split(ruleElement.operand.sParam, ":")
						} else {
							retMatch.Match.Ah.Not = ruleElement.not
							retMatch.Match.Ah.Spi = strings.Split(ruleElement.operand.sParam, ":")
						}

						hasOption = true
						handled = true
					}
				case "--ahlen":
					{
						retMatch.Match.AhIPv6.NotLength = ruleElement.not
						isNumber, n, _ := parseNumber(ruleElement.operand.sParam)
						if isNumber {
							retMatch.Match.AhIPv6.Length = n
						} else {
							parseErr.Line = row.lineNum
							parseErr.Msg = "Could not convert '" + ruleElement.operand.sParam + "' to integer"
							log.Panic(parseErr)
						}

						hasOption = true
						handled = true
					}
				case "--ahres":
					retMatch.Match.AhIPv6.Res = true

					hasOption = true
					handled = true
				}
			}
		case "bpf":
			{
				switch ruleElement.opcode {
				case "--bytecode":
					{
						retMatch.Match.Bpf.ByteCode = ruleElement.operand.sParam

						hasOption = true
						handled = true

						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case "cluster":
			{
				switch ruleElement.opcode {
				case "--cluster-total-nodes":
					{
						isNumber, n, _ := parseNumber(ruleElement.operand.sParam)
						if isNumber {
							retMatch.Match.Cluster.TotalNodes = n
						} else {
							parseErr.Line = row.lineNum
							parseErr.Msg = "Could not convert '" + ruleElement.operand.sParam + "' to integer"
							log.Panic(parseErr)
						}

						hasOption = true
						handled = true
					}
				case "--cluster-local-nodemask":
					{
						retMatch.Match.Cluster.NotLocalNodeMask = ruleElement.not
						isNumber, n, _ := parseNumber(ruleElement.operand.sParam)
						if isNumber {
							retMatch.Match.Cluster.LocalNodeMask = n
						} else {
							parseErr.Line = row.lineNum
							parseErr.Msg = "Could not convert '" + ruleElement.operand.sParam + "' to integer"
							log.Panic(parseErr)
						}

						hasOption = true
						handled = true
					}
				case "--cluster-hash-seed":
					{
						isNumber, n, _ := parseNumber(ruleElement.operand.sParam)
						if isNumber {
							retMatch.Match.Cluster.HashSeed = n
						} else {
							parseErr.Line = row.lineNum
							parseErr.Msg = "Could not convert '" + ruleElement.operand.sParam + "' to integer"
							log.Panic(parseErr)
						}

						hasOption = true
						handled = true
					}
				}
			}
		case "comment":
			{
				switch ruleElement.opcode {
				case "--comment":
					{
						retMatch.Match.Comment.Comment = ruleElement.operand.sParam
						//log.Printf("%d:\t\t\t\t>>> Parsed quoted text '%s'", row.lineNum, retMatch.Match.comment.comment)

						done = true // assume you can only encounter only once, opt out of the for{} loop now

						hasOption = true
						handled = true
					}
				}
			}
		case "connbytes":
			{
				switch ruleElement.opcode {
				case "--connbytes":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--connbytes-dir":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--connbytes-mode":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "connlabel":
			{
				switch ruleElement.opcode {
				case "--label":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--set":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "connlimit":
			{
				switch ruleElement.opcode {
				case "--connlimit-upto":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--connlimit-above":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--connlimit-mask":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--connlimit-saddr":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--connlimit-daddr":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "connmark":
			{
				switch ruleElement.opcode {
				case "--mark":
					{
						//
						hasOption = true
						handled = true

						done = true // assume you can only encounter only once, opt out of the for{} loop now

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "conntrack":
			{
				switch ruleElement.opcode {
				case "--ctstate":
					{
						retMatch.Match.Conntrack.NotStateList = ruleElement.not
						retMatch.Match.Conntrack.StateList = make([]ConnTrackState, len(ruleElement.operand.sParamList))
						for i, s := range ruleElement.operand.sParamList {
							retMatch.Match.Conntrack.StateList[i] = ConnTrackState(s)
						}

						hasOption = true
						handled = true
					}
				case "--ctproto":
					{
						retMatch.Match.Conntrack.NotProto = ruleElement.not
						retMatch.Match.Conntrack.L4Proto = ruleElement.operand.sParam

						hasOption = true
						handled = true
					}
				case "--ctorigsrc":
					{
						retMatch.Match.Conntrack.NotOriginalSrc = ruleElement.not
						retMatch.Match.Conntrack.OriginalSrc = ruleElement.operand.sParam

						hasOption = true
						handled = true
					}
				case "--ctorigdst":
					{
						retMatch.Match.Conntrack.NotOriginalDst = ruleElement.not
						retMatch.Match.Conntrack.OriginalDst = ruleElement.operand.sParam

						hasOption = true
						handled = true
					}
				case "--ctreplsrc":
					{
						retMatch.Match.Conntrack.NotReplySrc = ruleElement.not
						retMatch.Match.Conntrack.ReplySrc = ruleElement.operand.sParam

						hasOption = true
						handled = true
					}
				case "--ctrepldst":
					{
						retMatch.Match.Conntrack.NotReplyDst = ruleElement.not
						retMatch.Match.Conntrack.ReplyDst = ruleElement.operand.sParam

						hasOption = true
						handled = true
					}
				case "--ctorigsrcport":
					{
						retMatch.Match.Conntrack.NotOriginalSrcPort = ruleElement.not
						minmax := strings.Split(ruleElement.operand.sParam, ":")
						for j, s := range minmax {
							retMatch.Match.Conntrack.OriginalSrcPort[j] = lookupServicePort(s)
						}

						hasOption = true
						handled = true
					}
				case "--ctorigdstport":
					{
						retMatch.Match.Conntrack.NotOriginalDstPort = ruleElement.not
						minmax := strings.Split(ruleElement.operand.sParam, ":")
						for j, s := range minmax {
							retMatch.Match.Conntrack.OriginalDstPort[j] = lookupServicePort(s)
						}

						hasOption = true
						handled = true
					}
				case "--ctreplsrcport":
					{
						retMatch.Match.Conntrack.NotReplySrcPort = ruleElement.not
						minmax := strings.Split(ruleElement.operand.sParam, ":")
						for j, s := range minmax {
							retMatch.Match.Conntrack.ReplySrcPort[j] = lookupServicePort(s)
						}

						hasOption = true
						handled = true
					}
				case "--ctrepldstport":
					{
						retMatch.Match.Conntrack.NotReplyDstPort = ruleElement.not
						minmax := strings.Split(ruleElement.operand.sParam, ":")
						for j, s := range minmax {
							retMatch.Match.Conntrack.ReplyDstPort[j] = lookupServicePort(s)
						}

						hasOption = true
						handled = true
					}
				case "--ctstatus":
					{
						retMatch.Match.Conntrack.NotStatusList = ruleElement.not
						retMatch.Match.Conntrack.StatusList = make([]ConnTrackStatus, len(ruleElement.operand.sParamList))
						for i, s := range ruleElement.operand.sParamList {
							retMatch.Match.Conntrack.StatusList[i] = ConnTrackStatus(s)
						}

						hasOption = true
						handled = true
					}
				case "--ctexpire":
					{
						retMatch.Match.Conntrack.NotExpire = ruleElement.not
						// expiration time is in remaining lifetime of SECONDS (int) and can be in range (i.e. 45:90)
						for j, s := range ruleElement.operand.sPaired {
							isNumber, n, _ := parseNumber(s)
							if isNumber {
								retMatch.Match.Conntrack.Expire[j] = n
							}
						}

						hasOption = true
						handled = true
					}
				case "--ctdir":
					{
						switch ConnTrackDir(ruleElement.operand.sParam) {
						case CTDirOriginal:
							retMatch.Match.Conntrack.Dir = CTDirOriginal
						case CTDirReply:
							retMatch.Match.Conntrack.Dir = CTDirReply
						default:
							retMatch.Match.Conntrack.Dir = ConnTrackDir(ruleElement.operand.sParam)
						}

						hasOption = true
						handled = true
					}
				}
			}
		case "cpu":
			{
				switch ruleElement.opcode {
				case "--cpu":
					{
						//
						done = true // assume you can only encounter only once, opt out of the for{} loop now

						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "dccp":
			{
				switch ruleElement.opcode {
				case "--source-port", "--sport":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--destination-port", "--dport":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--dccp-types":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--dccp-option":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "devgroup":
			{
				switch ruleElement.opcode {
				case "--src-group":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--dst-group":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "dscp":
			{
				switch ruleElement.opcode {
				case "--dscp":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--dscp-class":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "dst":
			{
				switch ruleElement.opcode {
				case "--dst-len":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--dst-opts":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "ecn":
			{
				switch ruleElement.opcode {
				case "--ecn-tcp-cwr":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--ecn-tcp-ece":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--ecn-ip-ect":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "esp":
			{
				switch ruleElement.opcode {
				case "--espspi":
					{
						//
						done = true // assume you can only encounter only once, opt out of the for{} loop now

						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "eui64":
			{
				//
				done = true // assume you can only encounter only once, opt out of the for{} loop now

				hasOption = false // currently, this module has no options
				handled = true

				log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
				break
			}
		case "frag":
			{
				switch ruleElement.opcode {
				case "--fragid":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--fraglen":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--fragres":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--fragfirst":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--fragmore":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--fraglast":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "hashlimit":
			{
				switch ruleElement.opcode {
				case "--hashlimit-upto":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--hashlimit-above":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--hashlimit-burst":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--hashlimit-mode":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--hashlimit-srcmask":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--hashlimit-dstmask":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--hashlimit-name":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--hashlimit-htable-size":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--hashlimit-htable-max":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--hashlimit-htable-expire":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--hashlimit-htable-gcinterval":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "hbh":
			{
				switch ruleElement.opcode {
				case "--hbh-len":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--hbh-opts":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "helper":
			{
				switch ruleElement.opcode {
				case "--helper":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case "hl":
			{
				// hoplimit
				switch ruleElement.opcode {
				case "--hl-eq":
					{
						retMatch.Match.HlIPv6.Neq = ruleElement.not
						isNumber, n, _ := parseNumber(ruleElement.operand.sParam)
						if isNumber {
							retMatch.Match.HlIPv6.Eq = n
						} else {
							parseErr.Line = row.lineNum
							parseErr.Msg = "Could not convert '" + ruleElement.operand.sParam + "' to integer"
							log.Panic(parseErr)
						}

						hasOption = true
						handled = true
					}
				case "--hl-lt":
					{
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--hl-gt":
					{
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "icmp":
			{
				switch ruleElement.opcode {
				case "--icmp-type":
					{
						retMatch.Match.Icmp.Not = ruleElement.not
						retMatch.Match.Icmp.IcmpType = ruleElement.operand.sParam

						hasOption = true
						handled = true

						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case "icmp6":
			{
				switch ruleElement.opcode {
				case "--icmpv6-type":
					{
						retMatch.Match.Icmp6.Not = ruleElement.not
						retMatch.Match.Icmp6.Icmpv6Type = ruleElement.operand.sParam

						hasOption = true
						handled = true

						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case "iprange":
			{
				switch ruleElement.opcode {
				case "--src-range":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--dst-range":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "ipv6header":
			{
				switch ruleElement.opcode {
				case "--soft":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--header":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "ipvs":
			{
				switch ruleElement.opcode {
				case "--ipvs":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--vproto":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--vaddr":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--vport":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--vdir":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--vmethod":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--vportctl":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "length":
			{
				switch ruleElement.opcode {
				case "--length":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case "limit":
			{
				switch ruleElement.opcode {
				case "--limit":
					{
						retMatch.Match.Limit.Rate = ruleElement.operand.sParam

						hasOption = true
						handled = true
					}
				case "--limit-burst":
					{
						isNumber, n, _ := parseNumber(ruleElement.operand.sParam)
						if isNumber {
							retMatch.Match.Limit.Burst = n
						} else {
							parseErr.Line = row.lineNum
							parseErr.Msg = "Could not convert '" + ruleElement.operand.sParam + "' to integer"
							log.Panic(parseErr)
						}

						hasOption = true
						handled = true
					}
				}
			}
		case "mac":
			{
				switch ruleElement.opcode {
				case "--mac-source":
					{
						//
						hasOption = true
						handled = true

						done = true // assume you can only encounter only once, opt out of the for{} loop now

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "mark":
			{
				switch ruleElement.opcode {
				case "--mark":
					{
						//
						hasOption = true
						handled = true

						done = true // assume you can only encounter only once, opt out of the for{} loop now

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "mh":
			{
				switch ruleElement.opcode {
				case "--mh-type":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case "multiport":
			{
				switch ruleElement.opcode {
				case "--source-ports", "--sports":
					{
						retMatch.Match.Multiport.NotSPorts = ruleElement.not
						retMatch.Match.Multiport.Sports = strings.Split(ruleElement.operand.sParam, ",")

						hasOption = true
						handled = true
					}
				case "--destination-ports", "--dports":
					{
						retMatch.Match.Multiport.NotDPorts = ruleElement.not
						retMatch.Match.Multiport.Dports = strings.Split(ruleElement.operand.sParam, ",")

						hasOption = true
						handled = true
					}
				case "--ports":
					{
						retMatch.Match.Multiport.NotPorts = ruleElement.not
						retMatch.Match.Multiport.Ports = strings.Split(ruleElement.operand.sParam, ",")

						hasOption = true
						handled = true
					}
				}
			}
		case "nfacct":
			{
				switch ruleElement.opcode {
				case "--nfacct-name":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case "osf":
			{
				switch ruleElement.opcode {
				case "--genre":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--ttl":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--log":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "owner":
			{
				switch ruleElement.opcode {
				case "--uid-owner":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--gid-owner":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--socket-exist":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "physdev":
			{
				switch ruleElement.opcode {
				case "--physdev-in":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--physdev-out":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--physdev-is-in":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--physdev-is-out":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--physdev-is-bridged":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "pkttype":
			{
				switch ruleElement.opcode {
				case "--pkt-type":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case "policy":
			{
				switch ruleElement.opcode {
				case "--dir":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--pol":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--strict":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--reqid":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--spi":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--proto":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--mode":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--tunnel-src":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--tunnel-dst":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--next":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "quota":
			{
				switch ruleElement.opcode {
				case "--quota":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case "rateest":
			{
				switch ruleElement.opcode {
				case "--rateest-delta":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rateest-lt":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rateest-gt":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rateest-eq":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rateest":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rateest1":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rateest2":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rateest-bps":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rateest-pps":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rateest-bps1":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rateest-bps2":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rateest-pps1":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rateest-pps2":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "realm":
			{
				switch ruleElement.opcode {
				case "--realm":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case "recent":
			{
				switch ruleElement.opcode {
				case "--name":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--set":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rsource":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rdest":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--mask":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rcheck":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--update":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--remove":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--seconds":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--reap":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--hitcount":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rttl":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "rpfilter":
			{
				switch ruleElement.opcode {
				case "--loose":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--validmark":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--accept-local":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--invert":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "rt":
			{
				switch ruleElement.opcode {
				case "--rt-type":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rt-segsleft":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rt-len":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rt-0-res":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rt-0-addrs":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--rt-0-not-strict":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "sctp":
			{
				switch ruleElement.opcode {
				case "--source-port", "--sport":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--destination-port", "--dport":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--chunk-types":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "set":
			{
				switch ruleElement.opcode {
				case "--match-set":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--return-nomatch":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--update-counters":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--update-subcounters":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--packets-eq":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--packets-lt":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--packets-gt":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "-bytes-eq", "--bytes-eq": // NOTE: for both Debian and Gentoo, man iptables-extensions shows this with single '-' and not '--'
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--bytes-lt":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--bytes-gt":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "socket":
			{
				switch ruleElement.opcode {
				case "--transparent":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--nowildcard":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "state":
			{
				switch ruleElement.opcode {
				case "--state":
					{
						retMatch.Match.State.NotState = ruleElement.not
						retMatch.Match.State.StateList = make([]StateState, len(ruleElement.operand.sParamList))
						//log.Printf("%d:\t\t\t--state -> '%s' : List %v", row.lineNum, ruleElement.operand.sParam, ruleElement.operand.sParamList)
						for i, s := range ruleElement.operand.sParamList {
							retMatch.Match.State.StateList[i] = StateState(s)
							//log.Printf("%d:\t\t\t\t%d: %s", row.lineNum, i, retMatch.Match.state.stateList[i])
						}

						hasOption = true
						handled = true

						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case "statistic":
			{
				switch ruleElement.opcode {
				case "--mode":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--probability":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--every":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--packet":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "string":
			{
				switch ruleElement.opcode {
				case "--algo":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--from":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--to":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--string":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--hex-string":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "tcp":
			{
				switch ruleElement.opcode {
				case "--source-port", "--sport":
					{
						retMatch.Match.Tcp.NotSPort = ruleElement.not
						minmax := strings.Split(ruleElement.operand.sParam, ":")
						log.Printf("\t\t\t\t\t--sport %s\n", minmax)
						for j, s := range minmax {
							// Note: it could be because the port is defined as service value (i.e. port 22 = 'ssh')
							retMatch.Match.Tcp.Sport[j] = lookupServicePort(s)
						}

						hasOption = true
						handled = true
					}
				case "--destination-port", "--dport":
					{
						retMatch.Match.Tcp.NotDPort = ruleElement.not
						minmax := strings.Split(ruleElement.operand.sParam, ":")
						for j, s := range minmax {
							// Note: it could be because the port is defined as service value (i.e. port 22 = 'ssh')
							retMatch.Match.Tcp.Dport[j] = lookupServicePort(s)
						}

						hasOption = true
						handled = true
					}
				case "--tcp-flags":
					{
						retMatch.Match.Tcp.NotFlags = ruleElement.not
						retMatch.Match.Tcp.FlagsMask = strings.Split(ruleElement.operand.sParam, ",")
						retMatch.Match.Tcp.FlagsComp = strings.Split(ruleElement.operand.sParam, ",")

						hasOption = true
						handled = true
					}
				case "--syn":
					{
						retMatch.Match.Tcp.NotSyn = ruleElement.not
						retMatch.Match.Tcp.Syn = true

						hasOption = true
						handled = true
					}
				case "--tcp-option":
					{
						retMatch.Match.Tcp.NotOption = ruleElement.not
						isNumber, n, _ := parseNumber(ruleElement.operand.sParam)
						if isNumber {
							retMatch.Match.Tcp.Option = n
						} else {
							parseErr.Line = row.lineNum
							parseErr.Msg = "Could not convert '" + ruleElement.operand.sParam + "' to integer"
							log.Panic(parseErr)
						}

						hasOption = true
						handled = true
					}
				}
			}
		case "tcpmss":
			{
				switch ruleElement.opcode {
				case "--mss":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case "time":
			{
				switch ruleElement.opcode {
				case "--datestart":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--datestop":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--timestart":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--timestop":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--monthdays":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--weekdays":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--contiguous":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--kerneltz":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "tos":
			{
				switch ruleElement.opcode {
				case "--tos":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case "ttl":
			{
				switch ruleElement.opcode {
				case "--ttl-eq":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--ttl-gt":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				case "--ttl-lt":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
					}
				}
			}
		case "u32":
			{
				switch ruleElement.opcode {
				case "--u32":
					{
						//
						hasOption = true
						handled = true

						log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
						done = true // assume you can only encounter only once, opt out of the for{} loop now
					}
				}
			}
		case "udp":
			{
				switch ruleElement.opcode {
				case "--source-port", "--sport":
					{
						retMatch.Match.Udp.NotSPort = ruleElement.not
						minmax := strings.Split(ruleElement.operand.sParam, ":")
						//log.Printf("\t\t\t\t\tudp --sport range %s\n", minmax)
						for j, s := range minmax {
							retMatch.Match.Udp.Sport[j] = lookupServicePort(s)
							//log.Printf("\t\t\t\t\t\tudp --sport %s[%d] -> %d\n", s, j, retMatch.Match.udp.sport[j])
						}

						hasOption = true
						handled = true
					}
				case "--destination-port", "--dport":
					{
						retMatch.Match.Udp.NotDPort = ruleElement.not
						minmax := strings.Split(ruleElement.operand.sParam, ":")
						//log.Printf("\t\t\t\t\tudp --dport range %s\n", minmax)
						for j, s := range minmax {
							retMatch.Match.Udp.Dport[j] = lookupServicePort(s)
							//log.Printf("\t\t\t\t\t\tudp --dport %s[%d] -> %d\n", s, j, retMatch.Match.udp.dport[j])
						}

						hasOption = true
						handled = true
					}
				}
			}
		case "unclean":
			{
				done = true // assume you can only encounter only once, opt out of the for{} loop now

				handled = true
				hasOption = false // currently, this module has no options

				log.Panic("CODE ME! - " + retMatch.Module + " - " + ruleElement.opcode)
			}
		} // switch

		// debug logging
		if handled == false {
			//log.Printf("%d:\t\t\t\t\t\tMatch '%s' Unhandled option: '%s' with param '%s'\n", row.lineNum, matchModule.operand.sParam, ruleElement.opcode, ruleElement.operand.sParam)
		} else if hasOption {
			retMatch.Rule += " " + printDebugNot(ruleElement.not) + ruleElement.opcode + " " + ruleElement.operand.sParam
		} else if hasOption {
			log.Printf("%d:\t\t\t\t\t\tMatch '%s' does not expect any options, done=%v\n", row.lineNum, matchModule.operand.sParam, done)
		}
	} //for
	//log.Printf("%d:\t\t\t\t\tProcessed Match: '%s'\n", row.lineNum, retMatch.rule)
	return retMatch, parseErr
}

func appendUserDefined(udcList []UserDefinedChain, name TargetName, rule RuleSpec) []UserDefinedChain {
	for iUDC, udc := range udcList {
		if udc.Name == name {
			udcList[iUDC].Rules = append(udcList[iUDC].Rules, rule)
			//log.Printf("\t[%d] Existing chain %s, appending rule - rules count = %d\n", iUDC, udcList[iUDC].name, len(udcList[iUDC].rules))
			return udcList
		}
	}
	// if here, could not find chainName, so just add it as first
	var newRule []RuleSpec
	newRule = append(newRule, rule)
	newUDC := UserDefinedChain{
		Name:  name,
		Rules: newRule,
	}
	udcList = append(udcList, newUDC)
	//log.Printf("\tAdding new chain %s\n", name)
	return udcList
}

func parseFilter(lines map[int]string, isIPv6 bool) (TableFilter, ParseError) {
	var table TableFilter
	var err ParseError
	chains := findDefaultPolicies(lines)
	table.DefaultPolicies = chains
	textTable := buildTable("filter", lines, isIPv6)

	if len(textTable.rows) > 0 {
		for _, row := range textTable.rows {
			//log.Printf("filter[%d:%d] (%v) '%s'\n", row.lineNum, ri, row.commandArg, row.strRule)

			switch row.commandArg.command {
			case CommandInsert:
				{
					// insert chain [pos] rule - if pos is not there, it's same as append
					err.Line = row.lineNum
					err.Msg = "-I (insert) not currently supported"
					log.Panic(err)
				}
			case CommandAppend:
				{
					// append chain rule
					rule, err := parseRuleSpec(row, isIPv6)
					if err.Msg == "" {
						switch row.commandArg.chain {
						case ChainINPUT:
							table.BuiltInInput = append(table.BuiltInInput, rule)
						case ChainOUTPUT:
							table.BuiltInOutput = append(table.BuiltInOutput, rule)
						case ChainFORWARD:
							table.BuiltInForward = append(table.BuiltInForward, rule)
						default:
							// add it to UserDefinedChain
							//log.Printf("\tFound UserDefined Chain %s: %v\n", row.commandArg.chain, rule)
							table.Userdefined = appendUserDefined(table.Userdefined, TargetName(row.commandArg.chain), rule)
						}
					}
				}
			case CommandDelete:
				{
					// delete chain rule
					err.Line = row.lineNum
					err.Msg = "-D (delete) not currently supported"
					log.Panic(err)
				}
			case CommandReplace:
				{
					// replace chain pos spec
					err.Line = row.lineNum
					err.Msg = "-R (replace) not currently supported"
					log.Panic(err)
				}
			}
		}
	}
	return table, err
}

func parseNat(lines map[int]string, isIPv6 bool) (TableNat, ParseError) {
	var table TableNat
	var err ParseError
	chains := findDefaultPolicies(lines)
	table.DefaultPolicies = chains
	textTable := buildTable("nat", lines, isIPv6)

	if len(textTable.rows) > 0 {
		for _, row := range textTable.rows {
			//log.Printf("nat[%d:%d] (%v) '%s'\n", row.lineNum, ri, row.commandArg, row.strRule)

			switch row.commandArg.command {
			case CommandInsert:
				{
					// insert chain [pos] rule - if pos is not there, it's same as append
					err.Line = row.lineNum
					err.Msg = "-I (insert) not currently supported"
					log.Panic(err)
				}
			case CommandAppend:
				{
					// append chain rule
					rule, err := parseRuleSpec(row, isIPv6)
					if err.Msg == "" {
						switch row.commandArg.chain {
						case ChainPREROUTING:
							table.BuiltInPrerouting = append(table.BuiltInPrerouting, rule)
						case ChainOUTPUT:
							table.BuiltInOutput = append(table.BuiltInOutput, rule)
						case ChainPOSTROUTING:
							table.BuiltInPostrouting = append(table.BuiltInPostrouting, rule)
						default:
							// add it to UserDefinedChain
							//log.Printf("\tFound UserDefined Chain %s: %v\n", row.commandArg.chain, rule)
							table.Userdefined = appendUserDefined(table.Userdefined, TargetName(row.commandArg.chain), rule)
						}
					}
				}
			case CommandDelete:
				{
					// delete chain rule
					err.Line = row.lineNum
					err.Msg = "-D (delete) not currently supported"
					log.Panic(err)
				}
			case CommandReplace:
				{
					// replace chain pos spec
					err.Line = row.lineNum
					err.Msg = "-R (replace) not currently supported"
					log.Panic(err)
				}
			}
		}
	}
	return table, err
}

func parseMangle(lines map[int]string, isIPv6 bool) (TableMangle, ParseError) {
	var table TableMangle
	var err ParseError
	chains := findDefaultPolicies(lines)
	table.DefaultPolicies = chains
	textTable := buildTable("mangle", lines, isIPv6)

	if len(textTable.rows) > 0 {
		for _, row := range textTable.rows {
			//log.Printf("mangle[%d:%d] (%v) '%s'\n", row.lineNum, ri, row.commandArg, row.strRule)

			switch row.commandArg.command {
			case CommandInsert:
				{
					// insert chain [pos] rule - if pos is not there, it's same as append
					err.Line = row.lineNum
					err.Msg = "-I (insert) not currently supported"
					log.Panic(err)
				}
			case CommandAppend:
				{
					// append chain rule
					rule, err := parseRuleSpec(row, isIPv6)
					if err.Msg == "" {
						switch row.commandArg.chain {
						case ChainPREROUTING:
							table.BuiltInPrerouting = append(table.BuiltInPrerouting, rule)
						case ChainINPUT:
							table.BuiltInInput = append(table.BuiltInInput, rule)
						case ChainOUTPUT:
							table.BuiltInOutput = append(table.BuiltInOutput, rule)
						case ChainFORWARD:
							table.BuiltInForward = append(table.BuiltInForward, rule)
						case ChainPOSTROUTING:
							table.BuiltInPostrouting = append(table.BuiltInPostrouting, rule)
						default:
							// add it to UserDefinedChain
							//log.Printf("\tFound UserDefined Chain %s: %v\n", row.commandArg.chain, rule)
							table.Userdefined = appendUserDefined(table.Userdefined, TargetName(row.commandArg.chain), rule)
						}
					}
				}
			case CommandDelete:
				{
					// delete chain rule
					err.Line = row.lineNum
					err.Msg = "-D (delete) not currently supported"
					log.Panic(err)
				}
			case CommandReplace:
				{
					// replace chain pos spec
					err.Line = row.lineNum
					err.Msg = "-R (replace) not currently supported"
					log.Panic(err)
				}
			}
		}
	}
	return table, err
}

func parseRaw(lines map[int]string, isIPv6 bool) (TableRaw, ParseError) {
	var table TableRaw
	var err ParseError
	chains := findDefaultPolicies(lines)
	table.DefaultPolicies = chains
	textTable := buildTable("raw", lines, isIPv6)

	if len(textTable.rows) > 0 {
		for _, row := range textTable.rows {
			//log.Printf("raw[%d:%d] (%v) '%s'\n", row.lineNum, ri, row.commandArg, row.strRule)

			switch row.commandArg.command {
			case CommandInsert:
				{
					// insert chain [pos] rule - if pos is not there, it's same as append
					err.Line = row.lineNum
					err.Msg = "-I (insert) not currently supported"
					log.Panic(err)
				}
			case CommandAppend:
				{
					// append chain rule
					rule, err := parseRuleSpec(row, isIPv6)
					if err.Msg == "" {
						switch row.commandArg.chain {
						case ChainPREROUTING:
							table.BuiltInPrerouting = append(table.BuiltInPrerouting, rule)
						case ChainOUTPUT:
							table.BuiltInOutput = append(table.BuiltInOutput, rule)
						default:
							// add it to UserDefinedChain
							//log.Printf("\tFound UserDefined Chain %s: %v\n", row.commandArg.chain, rule)
							table.Userdefined = appendUserDefined(table.Userdefined, TargetName(row.commandArg.chain), rule)
						}
					}
				}
			case CommandDelete:
				{
					// delete chain rule
					err.Line = row.lineNum
					err.Msg = "-D (delete) not currently supported"
					log.Panic(err)
				}
			case CommandReplace:
				{
					// replace chain pos spec
					err.Line = row.lineNum
					err.Msg = "-R (replace) not currently supported"
					log.Panic(err)
				}
			}
		}
	}
	return table, err
}

func parseSecurity(lines map[int]string, isIPv6 bool) (TableSecurity, ParseError) {
	var table TableSecurity
	var err ParseError
	chains := findDefaultPolicies(lines)
	table.DefaultPolicies = chains
	textTable := buildTable("security", lines, isIPv6)

	if len(textTable.rows) > 0 {
		for _, row := range textTable.rows {
			//log.Printf("security[%d:%d] (%v) '%s'\n", row.lineNum, ri, row.commandArg, row.strRule)

			switch row.commandArg.command {
			case CommandInsert:
				{
					// insert chain [pos] rule - if pos is not there, it's same as append
					err.Line = row.lineNum
					err.Msg = "-I (insert) not currently supported"
					log.Panic(err)
				}
			case CommandAppend:
				{
					// append chain rule
					rule, err := parseRuleSpec(row, isIPv6)
					if err.Msg == "" {
						switch row.commandArg.chain {
						case ChainINPUT:
							table.BuiltInInput = append(table.BuiltInInput, rule)
						case ChainOUTPUT:
							table.BuiltInOutput = append(table.BuiltInOutput, rule)
						case ChainFORWARD:
							table.BuiltInForward = append(table.BuiltInForward, rule)
						default:
							// add it to UserDefinedChain
							//log.Printf("\tFound UserDefined Chain %s: %v\n", row.commandArg.chain, rule)
							table.Userdefined = appendUserDefined(table.Userdefined, TargetName(row.commandArg.chain), rule)
						}
					}
				}
			case CommandDelete:
				{
					// delete chain rule
					err.Line = row.lineNum
					err.Msg = "-D (delete) not currently supported"
					log.Panic(err)
				}
			case CommandReplace:
				{
					// replace chain pos spec
					err.Line = row.lineNum
					err.Msg = "-R (replace) not currently supported"
					log.Panic(err)
				}
			}
		}
	}
	return table, err
}
