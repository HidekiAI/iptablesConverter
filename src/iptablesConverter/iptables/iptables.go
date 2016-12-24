package iptables

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type KVP struct {
	key   interface{}
	value interface{}
}

type ParseError struct {
	line int
	msg  string
	err  error
}

// AddressFamily type representation
type AddressFamily int

const (
	// IPv4 is default
	IPv4 AddressFamily = iota + 1
	// IPv6 is less common
	IPv6
)

type Target string

const (
	// iptables TARGET
	TargetACCEPT Target = "ACCEPT"
	TargetDROP          = "DROP"
	TargetRETURN        = "RETURN"
	// iptables-extensions TARGET
	TargetAUDIT       = "AUDIT"
	TargetCHECKSUM    = "CHECKSUM"
	TargetCLASSIFY    = "CLASSIFY"
	TargetCLUSTERIPv4 = "CLUSTERIP"
	TargetCONNMARK    = "CONNMARK"
	TargetCONNSECMARK = "CONNSECMARK"
	TargetCT          = "CT"
	TargetDNAT        = "DNAT"
	TargetDNPTv6      = "DNPT"
	TargetDSCP        = "DSCP"
	TargetECNv4       = "ECN"
	TargetHLv6        = "HL"
	TargetHMARK       = "HMARK"
	TargetIDLETIMER   = "IDLETIMER"
	TargetLED         = "LED"
	TargetLOG         = "LOG"
	TargetMARK        = "MARK"
	TargetMASQUERADE  = "MASQUERADE"
	TargetMIRRORv4    = "MIRROR"
	TargetNETMAP      = "NETMAP"
	TargetNFLOG       = "NFLOG"
	TargetNFQUEUE     = "NFQUEUE"
	TargetNOTRACK     = "NOTRACK"
	TargetRATEEST     = "RATEEST"
	TargetREDIRECT    = "REDIRECT"
	TargetREJECTv4    = "REJECT"
	TargetREJECTv6    = "REJECT"
	TargetSAMEv4      = "SAME"
	TargetSECMARK     = "SECMARK"
	TargetSET         = "SET"
	TargetSNAT        = "SNAT"
	TargetSNPTv6      = "SNPT"
	TargetTCPMSS      = "TCPMSS"
	TargetTCPOPTSTRIP = "TCPOPTSTRIP"
	TargetTEE         = "TEE"
	TargetTOS         = "TOS"
	TargetPROXY       = "TPROXY"
	TargetTRACE       = "TRACE"
	TargetTTLv4       = "TTL"
	TargetULOGv4      = "ULOG"
)

// Chain represents default/built-in chains
type Chain struct {
	name   string
	line   int
	target Target
}

// UserDefinedChain are chains that are not built-in
type UserDefinedChain struct {
	chain Chain
	rules []RuleSpec
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
	rule   string            // preserve raw string, used in case where converter cannot handle
	module string            // i.e. '-m comment'
	match  RuleSpecExtension // i.e. '-m comment --comment "this is comment"'
}
type Interface string

// RuleSpec: see man 8 iptables
type RuleSpec struct {
	rule string // preserve raw string, used in case where converter cannot handle
	line int    // mainly for error purpose

	//family: i.e. '-4', '--ipv4', '-6', '--ipv6'
	family AddressFamily
	//protocol: [!] -p, --protocol protocol
	protocol struct {
		not bool     // i.e. '! -p tcp'
		p   Protocol // i.e. '-p udp'
	}
	// source: [!] -s, --source address[/mask],[,...]
	source struct {
		not bool // i.e. '-s 192.168.42.0/16,192.168.69.0/8', '! -s 127.0.0.1'
		s   Source
	}
	// destination: [!] -d, --destination address[/mask][,...]
	destination struct {
		not bool
		d   Destination // i.e. '-d 0.0.0.0/0', '-d ::1/128'
	}
	// match: -m, --match match
	match Match // i.e. '-m comment --comment "this is comment"'
	// jump: -j, --jump atarget
	jump Target // i.e. '-j ACCEPT'
	// goto: -g, --goto chain
	gotoChain Chain // i.e. '-g chainName'
	// inInterface: [!] -i, --in-interface name
	inInterface struct {
		not  bool // i.e. '-i lo', '! -i eth2'
		name Interface
	}
	//outInterface: [!] -o, --out-interface name
	outInterface struct {
		not  bool
		name Interface // i.e. '-o any'
	}
	// fragment: [!] -f, --fragment
	fragment struct {
		not bool // i.e. '-f', '! -f'
	}
	// Counters: -c, --set-counters packets, bytes
	counters struct {
		packets int
		bytes   int
	}
}

type AddressType string
type ConnTrackState string
type ConnTrackStatus string
type ConnTrackDir string

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
)

// RuleSpecExtension: see man 8 iptables-extensions
type RuleSpecExtension struct {
	// format: '-m name moduleoptions'
	// i.e. '-m comment --comment "this is a comment" -j log'
	addrtype struct {
		notSrc        bool
		srcType       AddressType
		notDst        bool
		dstType       AddressType
		limitIfaceIn  bool
		limitIfaceOut bool
	}
	ah struct {
		not bool
		spi []string
	}
	ahIPv6 struct {
		notSPI    bool
		spi       []string
		notLength bool
		length    int
		res       bool
	}
	bpf struct {
		// i.e. iptables -A OUTPUT -m bpf --bytecode '4,48 0 0 9,21 0 1 6,6 0 0 1,6 0 0 0' -j ACCEPT
		//	4               # number of instructions
		//	48 0 0 9        # load byte  ip->proto
		//	21 0 1 6        # jump equal IPPROTO_TCP
		//	6 0 0 1         # return     pass (non-zero)
		//	6 0 0 0         # return     fail (zero)
		// i.e. iptables -A OUTPUT -m bpf --bytecode "`nfbpf_compile RAW 'ip proto 6'`" -j ACCEPT
		byteCode string
	}
	cluster struct {
		totalNodes       int
		notLocalNodeMask bool
		localNodeMask    int
		hashSeed         int
	}
	comment struct {
		comment string
	}
	connbytes struct {
	}
	connlabel struct {
	}
	connlimit struct {
	}
	connmark struct {
	}
	conntrack struct {
		notStateList       bool
		stateList          []ConnTrackState // csv states to match of INVALID|NEW|ESTABLISHED|RELATED|UNTRACKED|SNAT|DNAT
		notProto           bool
		l4Proto            string // layer-4 protocol to match (by number or name)
		notOriginalSrc     bool
		originalSrc        string // address[/mask]
		notOriginalDst     bool
		originalDst        string
		notReplySrc        bool
		replySrc           string
		notReplyDst        bool
		replyDst           string
		notOriginalSrcPort bool
		originalSrcPort    [2]int // range, i.e. '--ctorigsrcport 1024:2048'
		notOriginalDstPort bool
		originalDstPort    [2]int
		notReplySrcPort    bool
		replySrcPort       [2]int
		notReplyDstPort    bool
		replyDstPort       [2]int
		notStatusList      bool
		statusList         []ConnTrackStatus // csv of NONE|EXPECTED|SEEN_REPLY|ASSURED|CONFIRMED
		notExpire          bool
		expire             [2]int       // remaining lifetime in seconds
		dir                ConnTrackDir // either ORIGINAL|REPLY
	}
	cpu struct {
	}
	dccp struct {
	}
	devgroup struct {
	}
	dscp struct {
	}
	dst struct {
	}
	ecn struct {
	}
	esp struct {
	}
	eui64IPv6 struct {
	}
	fragIPv6 struct {
	}
	hashlimit struct {
	}
	hbhIPv6 struct {
	}
	helper struct {
	}
	hlIPv6 struct {
	}
	icmp struct {
	}
	icmp6 struct {
	}
	iprange struct {
	}
	ipv6header struct {
	}
	ipvs struct {
	}
	length struct {
	}
	limit struct {
		rate  string // i.e. '3/hour'
		burst int
	}
	mac struct {
	}
	mark struct {
	}
	mhIPv6 struct {
	}
	multiport struct {
		notSPorts bool
		sports    []string // i.e. 53,1024:65535 means 53 and range 1024:65535
		notDPorts bool
		dports    []string
		notPorts  bool
		ports     []string
	}
	nfacct struct {
	}
	osf struct {
	}
	owner struct {
	}
	physdev struct {
	}
	pkttype struct {
	}
	policy struct {
	}
	quota struct {
	}
	rateest struct {
	}
	realmIPv4 struct {
	}
	recent struct {
	}
	rpfilter struct {
	}
	rtIPv6 struct {
	}
	sctp struct {
	}
	set struct {
	}
	socket struct {
	}
	state struct {
	}
	statistic struct {
	}
	stringMatch struct {
	}
	tcp struct {
		notSPort  bool
		sport     [2]int // ranged port (i.e. "--sport 1024:2048")
		notDPort  bool
		dport     [2]int // ranged
		notFlags  bool
		flagsMask []string // csv i.e. 'SYN,ACK,FIN,RST'
		flagsComp []string // csv what to be set i.e. 'ALL'
		notSyn    bool
		syn       bool
		notOption bool
		option    int
	}
	tcpmss struct {
	}
	time struct {
	}
	tos struct {
	}
	ttlIPv4 struct {
	}
	u32 struct {
	}
	udp struct {
		notSPort bool
		sport    [2]int
		notDPort bool
		dport    [2]int
	}
	uncleanIPv4 struct {
	}
}

//TableRaw represents the '*raw' table block
// see TABLES section from http://ipset.netfilter.org/iptables.man.html
type TableRaw struct {
	chains            []Chain
	builtInPrerouting []RuleSpec
	builtInOutput     []RuleSpec
	userdefined       []UserDefinedChain
}

//TableNat represents the '*nat' table block
type TableNat struct {
	chains             []Chain
	builtInPrerouting  []RuleSpec
	builtInOutput      []RuleSpec
	builtInPostrouting []RuleSpec
	userdefined        []UserDefinedChain
}

//TableMangle represents the '*mangle' table block
type TableMangle struct {
	chains             []Chain
	builtInPrerouting  []RuleSpec
	builtInOutput      []RuleSpec
	builtInInput       []RuleSpec
	builtInForward     []RuleSpec
	builtInPostrouting []RuleSpec
	userdefined        []UserDefinedChain
}

//TableFilter represents the '*filter' table block
type TableFilter struct {
	chains         []Chain
	builtInInput   []RuleSpec
	builtInForward []RuleSpec
	builtInOutput  []RuleSpec
	userdefined    []UserDefinedChain
}

//TableSecurity represents the '*security' table block
type TableSecurity struct {
	chains         []Chain
	builtInInput   []RuleSpec
	builtInOutput  []RuleSpec
	builtInForward []RuleSpec
	userdefined    []UserDefinedChain
}

//Iptables is a struct representing collections of tables
type Iptables struct {
	family   AddressFamily
	raw      TableRaw
	nat      TableNat
	mangle   TableMangle
	filter   TableFilter
	security TableSecurity
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
		panic(openErr)
	}
	defer file.Close()

	var filterBlock map[int]string = make(map[int]string, 0)
	var natBlock map[int]string = make(map[int]string, 0)
	var mangleBlock map[int]string = make(map[int]string, 0)
	var rawBlock map[int]string = make(map[int]string, 0)
	var securityBlock map[int]string = make(map[int]string, 0)
	var line string
	currentBlockRef := filterBlock // map is ref type 'map[int]string []'
	ret.family = IPv4
	scanner := bufio.NewScanner(file)
	lineCount := 1

	// Just collect lines from each blocks, no parsing are done in this for{} loop except to
	// filter out comments that starts with "#" on column 0, also trimmed off white spaces
	// at front and tail of each lines
	for scanner.Scan() {
		line = strings.TrimSpace(scanner.Text())
		if line != "" {

			if ret.family != IPv6 {
				if isIPv6(line) {
					ret.family = IPv6
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
				} else {
					// store line to current block
					currentBlockRef[lineCount] = line
				}
			}
		}
		lineCount++
	}

	// parse each blocks
	ret.filter, err = parseFilter(filterBlock, ret.family == IPv6)
	ret.mangle, err = parseMangle(mangleBlock, ret.family == IPv6)
	ret.nat, err = parseNat(natBlock, ret.family == IPv6)
	ret.raw, err = parseRaw(rawBlock, ret.family == IPv6)
	ret.security, err = parseSecurity(securityBlock, ret.family == IPv6)

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

func findChains(lines map[int]string) []Chain {
	var ret []Chain
	for key, value := range lines {
		if strings.HasPrefix(value, ":") {
			split := strings.Fields(strings.TrimLeft(value, ":"))
			ret = append(ret, Chain{name: split[0], target: Target(split[1]), line: key})
		}
	}
	return ret
}

func getParams(strList []string) (int, []string) {
	retCount := 0
	var parmList []string
	for retCount = 0; retCount < len(strList); retCount++ {
		s := strList[retCount]
		if strings.HasPrefix(s, "-") {
			break
		}
		parmList = append(parmList, s)
	}

	return retCount, parmList
}

func parseQuotedText(strList []string) (string, int) {
	retString := ""
	retCount := 0
	foundClosing := false
	// search for text which begins with "|' and ends with matching punctuations
	if strings.HasPrefix(strList[0], "\"") || strings.HasPrefix(strList[0], "'") {
		punctuation := strList[0][:1]
		retString = retString + strList[0] // including the punctuation
		retCount++
		for _, s := range strList[1:] {
			retCount++
			retString = retString + s
			if strings.HasSuffix(s, punctuation) {
				foundClosing = true
				break
			}
		}
	}
	if foundClosing == false {
		panic("Unable to find closing quote in the string-list passed")
	}
	return retString, retCount
}

func lookupServicePort(port string) int {
	p, err := strconv.Atoi(port)
	if err != nil {
		// use net.LookupPort() to see if we get anything
		p, err = net.LookupPort("tcp", port)
		if err != nil {
			p, err = net.LookupPort("udp", port)
			if err != nil {
				panic(err)
			}
		}
	}
	return p
}

func parseRuleSpec(rule []string, isIPv6 bool, lineNum int) (RuleSpec, ParseError) {
	retRule := RuleSpec{rule: strings.Join(rule, " ")}
	parseErr := ParseError{}
	for i := 0; i < len(rule); i++ {
		s := rule[i]
		not := false
		if s == "!" {
			not = true
			i++
			s = rule[i]
		}
		if strings.HasPrefix(s, "-") {
			// either -x or --xxx
			switch s {
			case "-4", "--ipv4":
				{
					retRule.family = IPv4
					if isIPv6 {
						parseErr.line = lineNum
						parseErr.msg = "Parse requested as IPv6, but found '--ipv4' in rules"
						panic(parseErr.msg)
					}
				}
			case "-6", "--ipv6":
				{
					retRule.family = IPv6
					if isIPv6 == false {
						parseErr.line = lineNum
						parseErr.msg = "Parse requested as IPv4, but found '--ipv6' in rules"
						panic(parseErr.msg)
					}
				}
			case "-p", "--protocol":
				{
					i++
					retRule.protocol.not = not
					retRule.protocol.p = Protocol(rule[i])
				}
			case "-s", "--source":
				{
					i++
					retRule.source.not = not
					csv := strings.Split(rule[i], ",")
					retRule.source.s = Source(csv)
				}
			case "-d", "--destination":
				{
					i++
					retRule.destination.not = not
					csv := strings.Split(rule[i], ",")
					retRule.destination.d = Destination(csv)
				}
			case "-m", "--match":
				{
					i++
					name := rule[i]
					i++
					var j int
					j, retRule.match, parseErr = parseMatch(name, rule[i:], isIPv6, lineNum)
					i = i + j
				}
			case "-j", "--jump":
				{
					i++
					retRule.jump = Target(rule[i])
				}
			case "-g", "--goto":
				{
					i++
					retRule.gotoChain = Chain{name: rule[i]}
				}
			case "-i", "--in-interface":
				{
					i++
					retRule.inInterface.not = not
					retRule.inInterface.name = Interface(rule[i])
				}
			case "-o", "--out-interface":
				{
					i++
					retRule.outInterface.not = not
					retRule.outInterface.name = Interface(rule[i])
				}
			case "-f", "--fragment":
				{
					panic("-f/--fragment currently unsupported")
				}
			case "-c", "--set-counters":
				{
					i++
					j, params := getParams(rule[i:])
					if j != 2 {
						panic("--set-counters expected 2 parameters, found " + strconv.Itoa(j))
					}
					i = i + j
					var errPackets, errBytes error
					retRule.counters.packets, errPackets = strconv.Atoi(params[0])
					retRule.counters.bytes, errBytes = strconv.Atoi(params[1])
					if errPackets != nil {
						panic("Cannot convert --set-counters packets parameter")
					}
					if errBytes != nil {
						panic("Cannot convert --set-counters bytes parameter")
					}
				}
			}
			i++
		}
	}
	return retRule, parseErr
}

func parseMatch(moduleName string, strList []string, isIPv6 bool, lineNum int) (int, Match, ParseError) {
	retCount := 0
	retMatch := Match{rule: "--match " + moduleName + " ", module: moduleName}
	parseErr := ParseError{}
	options := ""
	not := false
	for retCount = 0; retCount < len(strList); retCount++ {
		// all options either starts with '!' (i.e. '! --src-type LOCAL' or '--' (i.e. '--comment').
		// anything else (i.e. starts with '-' (single minus), etc are considered to be not based
		// on iptables-extensions type and signals as end of match
		s := strList[retCount]
		if s == "!" {
			not = true
			retCount++
			s = strList[retCount]
		}

		if strings.HasPrefix(s, "--") {
			options = s

			switch moduleName {
			case "addrtype":
				{
					switch options {
					case "--src-type":
						{
							retMatch.match.addrtype.notSrc = not
							retCount++
							retMatch.match.addrtype.srcType = AddressType(strList[retCount])
						}
					case "--dst-type":
						{
							retMatch.match.addrtype.notDst = not
							retCount++
							retMatch.match.addrtype.dstType = AddressType(strList[retCount])
						}
					case "--limit-iface-in":
						{
							retMatch.match.addrtype.limitIfaceIn = true
						}
					case "--limit-iface-out":
						{
							retMatch.match.addrtype.limitIfaceOut = true
						}
					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
				}
			case "ah":
				{
					switch options {
					case "--ahspi":
						{
							if isIPv6 {
								retMatch.match.ahIPv6.notSPI = not
								retCount++
								retMatch.match.ahIPv6.spi = strings.Split(strList[retCount], ":")
							} else {
								retMatch.match.ah.not = not
								retCount++
								retMatch.match.ah.spi = strings.Split(strList[retCount], ":")
							}
						}
					case "--ahlen":
						{
							retMatch.match.ahIPv6.notLength = not
							var convErr error
							retCount++
							retMatch.match.ahIPv6.length, convErr = strconv.Atoi(strList[retCount])
							if convErr != nil {
								parseErr.line = lineNum
								parseErr.err = convErr
								parseErr.msg = "Could not convert '" + strList[retCount] + "' to integer"
								panic(parseErr.err)
							}
						}
					case "--ahres":
						retMatch.match.ahIPv6.res = true

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
				}
			case "bpf":
				{
					switch options {
					case "--bytecode":
						{
							retCount++
							quotedText, c := parseQuotedText(strList[retCount:])
							retCount = retCount + c
							retMatch.match.bpf.byteCode = quotedText
						}

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
				}
			case "cluster":
				{
					switch options {
					case "--cluster-total-nodes":
						{
							retCount++
							var convErr error
							retMatch.match.cluster.totalNodes, convErr = strconv.Atoi(strList[retCount])
							if convErr != nil {
								parseErr.line = lineNum
								parseErr.err = convErr
								parseErr.msg = "Could not convert '" + strList[retCount] + "' to integer"
								panic(parseErr.err)
							}
						}
					case "--cluster-local-nodemask":
						{
							retMatch.match.cluster.notLocalNodeMask = not
							retCount++
							var convErr error
							retMatch.match.cluster.localNodeMask, convErr = strconv.Atoi(strList[retCount])
							if convErr != nil {
								parseErr.line = lineNum
								parseErr.err = convErr
								parseErr.msg = "Could not convert '" + strList[retCount] + "' to integer"
								panic(parseErr.err)
							}
						}
					case "--cluster-hash-seed":
						{
							retCount++
							var convErr error
							retMatch.match.cluster.hashSeed, convErr = strconv.Atoi(strList[retCount])
							if convErr != nil {
								parseErr.line = lineNum
								parseErr.err = convErr
								parseErr.msg = "Could not convert '" + strList[retCount] + "' to integer"
								panic(parseErr.err)
							}
						}

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
				}
			case "comment":
				{
					switch options {
					case "--comment":
						{
							retCount++
							quotedText, c := parseQuotedText(strList[retCount:])
							retCount = retCount + c
							retMatch.match.comment.comment = quotedText
						}
					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
				}
			case "connbytes":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "connlabel":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "connlimit":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "conntrack":
				{
					switch options {
					case "--ctstate":
						{
							retMatch.match.conntrack.notStateList = not
							retCount++
							csv := strings.Split(strList[retCount], ",")
							retMatch.match.conntrack.stateList = make([]ConnTrackState, len(csv))
							for i, s := range csv {
								retMatch.match.conntrack.stateList[i] = ConnTrackState(s)
							}
						}
					case "--ctproto":
						{
							retMatch.match.conntrack.notProto = not
							retCount++
							retMatch.match.conntrack.l4Proto = strList[retCount]
						}
					case "--ctorigsrc":
						{
							retMatch.match.conntrack.notOriginalSrc = not
							retCount++
							retMatch.match.conntrack.originalSrc = strList[retCount]
						}
					case "--ctorigdst":
						{
							retMatch.match.conntrack.notOriginalDst = not
							retCount++
							retMatch.match.conntrack.originalDst = strList[retCount]
						}
					case "--ctreplsrc":
						{
							retMatch.match.conntrack.notReplySrc = not
							retCount++
							retMatch.match.conntrack.replySrc = strList[retCount]
						}
					case "--ctrepldst":
						{
							retMatch.match.conntrack.notReplyDst = not
							retCount++
							retMatch.match.conntrack.replyDst = strList[retCount]
						}
					case "--ctorigsrcport":
						{
							retMatch.match.conntrack.notOriginalSrcPort = not
							retCount++
							split := strings.Split(strList[retCount], ":")
							for j, s := range split {
								retMatch.match.conntrack.originalSrcPort[j] = lookupServicePort(s)
							}
						}
					case "--ctorigdstport":
						{
							retMatch.match.conntrack.notOriginalDstPort = not
							retCount++
							split := strings.Split(strList[retCount], ":")
							for j, s := range split {
								retMatch.match.conntrack.originalDstPort[j] = lookupServicePort(s)
							}
						}
					case "--ctreplsrcport":
						{
							retMatch.match.conntrack.notReplySrcPort = not
							retCount++
							split := strings.Split(strList[retCount], ":")
							for j, s := range split {
								retMatch.match.conntrack.replySrcPort[j] = lookupServicePort(s)
							}
						}
					case "--ctrepldstport":
						{
							retMatch.match.conntrack.notReplyDstPort = not
							retCount++
							split := strings.Split(strList[retCount], ":")
							for j, s := range split {
								retMatch.match.conntrack.replyDstPort[j] = lookupServicePort(s)
							}
						}
					case "--ctstatus":
						{
							retMatch.match.conntrack.notStatusList = not
							retCount++
							csv := strings.Split(strList[retCount], ",")
							retMatch.match.conntrack.statusList = make([]ConnTrackStatus, len(csv))
							for i, s := range csv {
								retMatch.match.conntrack.statusList[i] = ConnTrackStatus(s)
							}
						}
					case "--ctexpire":
						{
							retMatch.match.conntrack.notExpire = not
							retCount++
							// expiration time is in remaining lifetime of SECONDS (int) and can be in range (i.e. 45:90)
							split := strings.Split(strList[retCount], ":")
							for j, s := range split {
								i, convErr := strconv.Atoi(s)
								if convErr == nil {
									retMatch.match.conntrack.expire[j] = i
								}
							}
						}
					case "--ctdir":
						{
							retCount++
							switch ConnTrackDir(strList[retCount]) {
							case CTDirOriginal:
								retMatch.match.conntrack.dir = CTDirOriginal
							case CTDirReply:
								retMatch.match.conntrack.dir = CTDirReply
							default:
								retMatch.match.conntrack.dir = ConnTrackDir(strList[retCount])
							}
						}

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
				}
			case "cpu":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "dccp":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "devgroup":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "dscp":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "dst":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "ecn":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "esp":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "eui64":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "frag":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "hashlimit":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "hbh":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "helper":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "hl":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "icmp":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "icmp6":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "iprange":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "ipv6header":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "ipvs":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "length":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "limit":
				{
					switch options {
					case "--limit":
						{
							retCount++
							retMatch.match.limit.rate = strList[retCount]
						}
					case "--limit-burst":
						{
							retCount++
							i, convErr := strconv.Atoi(strList[retCount])
							if convErr != nil {
								parseErr.line = lineNum
								parseErr.err = convErr
								parseErr.msg = "Could not convert '" + strList[retCount] + "' to integer"
								panic(parseErr.err)
							}
							retMatch.match.limit.burst = i
						}

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
				}
			case "mac":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "mark":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "mh":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "multiport":
				{
					switch options {
					case "--source-ports", "--sports":
						{
							retCount++
							retMatch.match.multiport.notSPorts = not
							retMatch.match.multiport.sports = strings.Split(strList[retCount], ",")
						}
					case "--destination-ports", "--dports":
						{
							retCount++
							retMatch.match.multiport.notDPorts = not
							retMatch.match.multiport.dports = strings.Split(strList[retCount], ",")
						}
					case "--ports":
						{
							retCount++
							retMatch.match.multiport.notPorts = not
							retMatch.match.multiport.ports = strings.Split(strList[retCount], ",")
						}

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
				}
			case "nfacct":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "osf":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "owner":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "physdev":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "pkttype":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "policy":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "quota":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "rateest":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "realm":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "recent":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "rpfilter":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "rt":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "sctp":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "set":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "socket":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "state":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "statistic":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "string":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "tcp":
				{
					switch options {
					case "--source-port", "--sport":
						{
							retCount++
							retMatch.match.tcp.notSPort = not
							csv := strings.Split(strList[retCount], ":")
							for j, s := range csv {
								// Note: it could be because the port is defined as service value (i.e. port 22 = 'ssh')
								retMatch.match.tcp.sport[j] = lookupServicePort(s)
							}
						}
					case "--destination-port", "--dport":
						{
							retCount++
							retMatch.match.tcp.notDPort = not
							csv := strings.Split(strList[retCount], ":")
							for j, s := range csv {
								// Note: it could be because the port is defined as service value (i.e. port 22 = 'ssh')
								retMatch.match.tcp.dport[j] = lookupServicePort(s)
							}
						}
					case "--tcp-flags":
						{
							retCount++
							retMatch.match.tcp.notFlags = not
							retMatch.match.tcp.flagsMask = strings.Split(strList[retCount], ",")
							retCount++
							retMatch.match.tcp.flagsComp = strings.Split(strList[retCount], ",")
						}
					case "--syn":
						{
							retMatch.match.tcp.notSyn = not
							retMatch.match.tcp.syn = true
						}
					case "--tcp-option":
						{
							retCount++
							retMatch.match.tcp.notOption = not
							i, convErr := strconv.Atoi(strList[retCount])
							if convErr != nil {
								parseErr.line = lineNum
								parseErr.err = convErr
								parseErr.msg = "Could not convert '" + strList[retCount] + "' to integer"
								panic(parseErr.err)
							}
							retMatch.match.tcp.option = i
						}

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
				}
			case "tcpmss":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "time":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "tos":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "ttl":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "u32":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			case "udp":
				{
					switch options {
					case "--source-port", "--sport":
						{
							retMatch.match.udp.notSPort = not
							retCount++
							split := strings.Split(strList[retCount], ":")
							for j, s := range split {
								retMatch.match.udp.sport[j] = lookupServicePort(s)
							}
						}
					case "--destination-port", "--dport":
						{
							retMatch.match.udp.notDPort = not
							retCount++
							split := strings.Split(strList[retCount], ":")
							for j, s := range split {
								retMatch.match.udp.dport[j] = lookupServicePort(s)
							}
						}

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
				}
			case "unclean":
				{
					switch options {

					default:
						// none of the expected options for module, so we are done with this Match
						retCount-- // rewind
						break
					}
					panic("CODE ME! - " + moduleName + " - " + options)
				}
			}
			retCount++
		} else {
			// we're done for this '-m match', opt out of this for{} loop
			break
		}
	}
	return retCount, retMatch, parseErr
}

func appendUserDefined(udc []UserDefinedChain, chainName string, rule RuleSpec) []UserDefinedChain {
	for iUDC, chain := range udc {
		if chain.chain.name == chainName {
			//fmt.Printf("\t[%d] Existing chain %s, appending rule - rules count = ",iUDC, udc[iUDC].chain.name)
			udc[iUDC].rules = append(udc[iUDC].rules, rule)
			//fmt.Printf("%d\n", len(udc[iUDC].rules))
			return udc
		}
	}
	// if here, could not find chainName, so just add it as first
	var newRule []RuleSpec
	newRule = append(newRule, rule)
	newChain := Chain{
		name: chainName,
	}
	newUDC := UserDefinedChain{
		chain: newChain,
		rules: newRule,
	}
	udc = append(udc, newUDC)
	//fmt.Printf("\tAdding new chain %s\n", newChain.name)
	return udc
}

func parseFilter(lines map[int]string, isIPv6 bool) (TableFilter, ParseError) {
	var table TableFilter
	var err ParseError
	chains := findChains(lines)
	table.chains = chains

	for key, value := range lines {
		fmt.Printf("%d > '%s'\n", key, value)
		split := strings.Fields(strings.TrimSpace(value))
		switch split[0] {
		case "-I":
			// insert chain [pos] rule - if pos is not there, it's same as append
			pos, convErr := strconv.Atoi(split[2])
			if convErr == nil {
				// it's a number
				if key < pos {
					panic("Cannot insert")
				}
			} else {
				// no pos exist, so treat as append
			}
			err.line = key
			err.msg = "-I (insert) not currently supported"
			panic(err.err)
		case "-A":
			// append chain rule
			rule, err := parseRuleSpec(split[2:], isIPv6, key)
			if err.msg == "" {
				switch split[1] {
				case "INPUT":
					table.builtInInput = append(table.builtInInput, rule)
				case "OUTPUT":
					table.builtInOutput = append(table.builtInOutput, rule)
				case "FORWARD":
					table.builtInForward = append(table.builtInForward, rule)
				default:
					// add it to UserDefinedChain
					//fmt.Printf("Found %s: %s\n", split[1], rule)
					table.userdefined = appendUserDefined(table.userdefined, split[1], rule)
				}
			}
		case "-D":
			// delete chain rule
			err.line = key
			err.msg = "-D (delete) not currently supported"
			panic(err.err)
		case "-R":
			// replace chain pos spec
			err.line = key
			err.msg = "-R (replace) not currently supported"
			panic(err.err)
		}
	}

	return table, err
}

func parseNat(lines map[int]string, isIPv6 bool) (TableNat, ParseError) {
	var table TableNat
	var err ParseError
	chains := findChains(lines)
	table.chains = chains

	for key, value := range lines {
		split := strings.Fields(strings.TrimSpace(value))
		switch split[0] {
		case "-I":
			// insert chain [pos] rule - if pos is not there, it's same as append
			err.line = key
			err.msg = "-I (insert) not currently supported"
			panic(err.err)
		case "-A":
			// append chain rule
			rule, err := parseRuleSpec(split[2:], isIPv6, key)
			if err.msg == "" {
				switch split[1] {
				case "PREROUTING ":
					table.builtInPrerouting = append(table.builtInPrerouting, rule)
				case "OUTPUT":
					table.builtInOutput = append(table.builtInOutput, rule)
				case "POSTROUTING":
					table.builtInPostrouting = append(table.builtInPostrouting, rule)
				default:
					table.userdefined = appendUserDefined(table.userdefined, split[1], rule)
				}
			}
		case "-D":
			// delete chain rule
			err.line = key
			err.msg = "-D (delete) not currently supported"
			panic(err.err)
		case "-R":
			// replace chain pos spec
			err.line = key
			err.msg = "-R (replace) not currently supported"
			panic(err.err)
		}
	}

	return table, err
}

func parseMangle(lines map[int]string, isIPv6 bool) (TableMangle, ParseError) {
	var table TableMangle
	var err ParseError
	chains := findChains(lines)
	table.chains = chains

	for key, value := range lines {
		split := strings.Fields(strings.TrimSpace(value))
		switch split[0] {
		case "-I":
			// insert chain [pos] rule - if pos is not there, it's same as append
			err.line = key
			err.msg = "-I (insert) not currently supported"
			panic(err.err)
		case "-A":
			// append chain rule
			rule := RuleSpec{rule: strings.Join(split[2:], " ")}
			rule, err := parseRuleSpec(split[2:], isIPv6, key)
			if err.msg == "" {
				switch split[1] {
				case "PREROUTING":
					table.builtInPrerouting = append(table.builtInPrerouting, rule)
				case "INPUT":
					table.builtInInput = append(table.builtInInput, rule)
				case "OUTPUT":
					table.builtInOutput = append(table.builtInOutput, rule)
				case "FORWARD":
					table.builtInForward = append(table.builtInForward, rule)
				case "POSTROUTING":
					table.builtInPostrouting = append(table.builtInPostrouting, rule)
				default:
					table.userdefined = appendUserDefined(table.userdefined, split[1], rule)
				}
			}
		case "-D":
			// delete chain rule
			err.line = key
			err.msg = "-D (delete) not currently supported"
			panic(err.err)
		case "-R":
			// replace chain pos spec
			err.line = key
			err.msg = "-R (replace) not currently supported"
			panic(err.err)
		}
	}

	return table, err
}

func parseRaw(lines map[int]string, isIPv6 bool) (TableRaw, ParseError) {
	var table TableRaw
	var err ParseError
	chains := findChains(lines)
	table.chains = chains

	for key, value := range lines {
		split := strings.Fields(strings.TrimSpace(value))
		switch split[0] {
		case "-I":
			// insert chain [pos] rule - if pos is not there, it's same as append
			err.line = key
			err.msg = "-I (insert) not currently supported"
			panic(err.err)
		case "-A":
			// append chain rule
			rule, err := parseRuleSpec(split[2:], isIPv6, key)
			if err.msg == "" {
				switch split[1] {
				case "PREROUTING":
					table.builtInPrerouting = append(table.builtInPrerouting, rule)
				case "OUTPUT":
					table.builtInOutput = append(table.builtInOutput, rule)
				default:
					table.userdefined = appendUserDefined(table.userdefined, split[1], rule)
				}
			}
		case "-D":
			// delete chain rule
			err.line = key
			err.msg = "-D (delete) not currently supported"
			panic(err.err)
		case "-R":
			// replace chain pos spec
			err.line = key
			err.msg = "-R (replace) not currently supported"
			panic(err.err)
		}
	}

	return table, err
}

func parseSecurity(lines map[int]string, isIPv6 bool) (TableSecurity, ParseError) {
	var table TableSecurity
	var err ParseError
	chains := findChains(lines)
	table.chains = chains

	for key, value := range lines {
		split := strings.Fields(strings.TrimSpace(value))
		switch split[0] {
		case "-I":
			// insert chain [pos] rule - if pos is not there, it's same as append
			err.line = key
			err.msg = "-I (insert) not currently supported"
			panic(err.err)
		case "-A":
			// append chain rule
			rule, err := parseRuleSpec(split[2:], isIPv6, key)
			if err.msg == "" {
				switch split[1] {
				case "INPUT":
					table.builtInInput = append(table.builtInInput, rule)
				case "OUTPUT":
					table.builtInOutput = append(table.builtInOutput, rule)
				case "FORWARD":
					table.builtInForward = append(table.builtInForward, rule)
				default:
					table.userdefined = appendUserDefined(table.userdefined, split[1], rule)
				}
			}
		case "-D":
			// delete chain rule
			err.line = key
			err.msg = "-D (delete) not currently supported"
			panic(err.err)
		case "-R":
			// replace chain pos spec
			err.line = key
			err.msg = "-R (replace) not currently supported"
			panic(err.err)
		}
	}

	return table, err
}
