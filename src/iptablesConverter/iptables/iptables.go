package iptables

import (
    "bufio"
    "os"
    "strconv"
    "strings"
    //"fmt"
    //"go/types"
)

type KVP struct {
    key   interface{}
    value interface{}
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
    name string            // i.e. '-m comment'
    rule RuleSpecExtension // i.e. '-m comment --comment "this is comment"'
}
type Interface string

// RuleSpec: see man 8 iptables
type RuleSpec struct {
    rule     string
    protocol struct {
        not bool     // i.e. '! -p tcp'
        p   Protocol // i.e. '-p udp'
    }
    source struct {
        not bool // i.e. '-s 192.168.42.0/16,192.168.69.0/8', '! -s 127.0.0.1'
        s   Source
    }
    destination struct {
        not bool
        d   Destination // i.e. '-d 0.0.0.0/0', '-d ::1/128'
    }
    match       Match  // i.e. '-m comment --comment "this is comment"'
    jump        Target // i.e. '-j ACCEPT'
    gotoChain   Chain  // i.e. '-g chainName'
    inInterface struct {
        not  bool // i.e. '-i lo', '! -i eth2'
        name Interface
    }
    outInterface struct {
        not  bool
        name Interface // i.e. '-o any'
    }
    fragment struct {
        not bool // i.e. '-f', '! -f'
    }
    counters struct {
        packets int32
        bytes   int32
    }
}

// RuleSpecExtension: see man 8 iptables-extensions
type RuleSpecExtension struct {
    // format: '-m name moduleoptions'
    // i.e. '-m comment --comment "this is a comment" -j log'
    addrtype struct {
    }
    ahIPv6 struct {
    }
    ah struct {
    }
    bpf struct {
    }
    custer struct {
    }
    comment struct {
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
    }
    mac struct {
    }
    mark struct {
    }
    mhIPv6 struct {
    }
    multiport struct {
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
func Read(path string) Iptables {
    ret := Iptables{}
    file, err := os.Open(path)
    if err != nil {
        return ret
    }
    defer file.Close()

    var filterBlock []string
    var natBlock []string
    var mangleBlock []string
    var rawBlock []string
    var securityBlock []string
    var line string
    var currentBlockPtr *[]string
    ret.family = IPv4
    currentBlockPtr = &filterBlock
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line = strings.Trim(scanner.Text(), " \t")

        if ret.family != IPv6 {
            if isIPv6(line) {
                ret.family = IPv6
            }
        }

        // ignore # comments
        if strings.HasPrefix(line, "#") == false {
            if strings.HasPrefix(line, "*") == true {
                if strings.Contains(line, "*filter") {
                    currentBlockPtr = &filterBlock
                } else if strings.Contains(line, "*nat") {
                    currentBlockPtr = &natBlock
                } else if strings.Contains(line, "*mangle") {
                    currentBlockPtr = &mangleBlock
                } else if strings.Contains(line, "*raw") {
                    currentBlockPtr = &rawBlock
                } else if strings.Contains(line, "*security") {
                    currentBlockPtr = &securityBlock
                }
            } else {
                *currentBlockPtr = append(*currentBlockPtr, line)
            }
        }
    }

    // read each blocks
    ret.filter = parseFilter(filterBlock)
    ret.mangle = parseMangle(mangleBlock)
    ret.nat = parseNat(natBlock)
    ret.raw = parseRaw(rawBlock)
    ret.security = parseSecurity(securityBlock)

    return ret
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

func findChains(lines []string) []Chain {
    var ret []Chain
    for _, line := range lines {
        if strings.HasPrefix(line, ":") {
            split := strings.Split(strings.TrimLeft(line, ":"), " ")
            ret = append(ret, Chain{name: split[0], target: Target(split[1])})
        }
    }
    return ret
}
func parseRuleSpec(rule string) RuleSpec {
    split := strings.Split(rule, " \t")
    for i := 0; i < len(split); i++ {
        s := split[i]
        not := false
        if s == "!" {
            not = true
            i++
        }
        if strings.HasPrefix(i, "-") {
            // either -x or --xxx
            switch s {
            case "-j" || "--jump":
                
            }
        }
    }
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

func parseFilter(lines []string) TableFilter {
    var table TableFilter
    chains := findChains(lines)
    table.chains = chains

    for i, line := range lines {
        split := strings.Split(strings.Trim(line, " \t"), " ")
        switch split[0] {
        case "-I":
            // insert chain [pos] rule - if pos is not there, it's same as append
            pos, err := strconv.Atoi(split[2])
            if err == nil {
                // it's a number
                if i < pos {
                    panic("Cannot insert")
                }
            } else {
                // no pos exist, so treat as append
            }
        case "-A":
            // append chain rule
            rule := RuleSpec{rule: strings.Join(split[2:], " ")}
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
        case "-D":
            // delete chain rule
            panic("-D (delete) not currently supported")
        case "-R":
            // replace chain pos spec
            panic("-R (replace) not currently supported")
        }
    }

    return table
}

func parseNat(lines []string) TableNat {
    var table TableNat
    chains := findChains(lines)
    table.chains = chains

    for _, line := range lines {
        split := strings.Split(strings.Trim(line, " \t"), " ")
        switch split[0] {
        case "-I":
            // insert chain [pos] rule - if pos is not there, it's same as append
            panic("-I (insert) not currently supported")
        case "-A":
            // append chain rule
            rule := RuleSpec{rule: strings.Join(split[2:], " ")}
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
        case "-D":
            // delete chain rule
            panic("-D (delete) not currently supported")
        case "-R":
            // replace chain pos spec
            panic("-R (replace) not currently supported")
        }
    }

    return table
}

func parseMangle(lines []string) TableMangle {
    var table TableMangle
    chains := findChains(lines)
    table.chains = chains

    for _, line := range lines {
        split := strings.Split(strings.Trim(line, " \t"), " ")
        switch split[0] {
        case "-I":
            // insert chain [pos] rule - if pos is not there, it's same as append
            panic("-I (insert) not currently supported")
        case "-A":
            // append chain rule
            rule := RuleSpec{rule: strings.Join(split[2:], " ")}
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
        case "-D":
            // delete chain rule
            panic("-D (delete) not currently supported")
        case "-R":
            // replace chain pos spec
            panic("-R (replace) not currently supported")
        }
    }

    return table
}

func parseRaw(lines []string) TableRaw {
    var table TableRaw
    chains := findChains(lines)
    table.chains = chains

    for _, line := range lines {
        split := strings.Split(strings.Trim(line, " \t"), " ")
        switch split[0] {
        case "-I":
            // insert chain [pos] rule - if pos is not there, it's same as append
            panic("-I (insert) not currently supported")
        case "-A":
            // append chain rule
            rule := RuleSpec{rule: strings.Join(split[2:], " ")}
            switch split[1] {
            case "PREROUTING":
                table.builtInPrerouting = append(table.builtInPrerouting, rule)
            case "OUTPUT":
                table.builtInOutput = append(table.builtInOutput, rule)
            default:
                table.userdefined = appendUserDefined(table.userdefined, split[1], rule)
            }
        case "-D":
            // delete chain rule
            panic("-D (delete) not currently supported")
        case "-R":
            // replace chain pos spec
            panic("-R (replace) not currently supported")
        }
    }

    return table
}

func parseSecurity(lines []string) TableSecurity {
    var table TableSecurity
    chains := findChains(lines)
    table.chains = chains

    for _, line := range lines {
        split := strings.Split(strings.Trim(line, " \t"), " ")
        switch split[0] {
        case "-I":
            // insert chain [pos] rule - if pos is not there, it's same as append
            panic("-I (insert) not currently supported")
        case "-A":
            // append chain rule
            rule := RuleSpec{rule: strings.Join(split[2:], " ")}
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
        case "-D":
            // delete chain rule
            panic("-D (delete) not currently supported")
        case "-R":
            // replace chain pos spec
            panic("-R (replace) not currently supported")
        }
    }

    return table
}
