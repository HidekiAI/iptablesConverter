package iptables

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

type Protocol int

const (
	IPv4 Protocol = iota
	IPv6
)

type Chain struct {
	name   string
	target string
}

type UserDefinedChain struct {
	chain Chain
	rules []string
}

// see TABLES section from http://ipset.netfilter.org/iptables.man.html
type TableRaw struct {
	chains            []Chain
	builtInPrerouting []string
	builtInOutput     []string
	userdefined       []UserDefinedChain
}
type TableNat struct {
	chains             []Chain
	builtInPrerouting  []string
	builtInOutput      []string
	builtInPostrouting []string
	userdefined        []UserDefinedChain
}
type TableMangle struct {
	chains             []Chain
	builtInPrerouting  []string
	builtInOutput      []string
	builtInInput       []string
	builtInForward     []string
	builtInPostrouting []string
	userdefined        []UserDefinedChain
}
type TableFilter struct {
	chains         []Chain
	builtInInput   []string
	builtInForward []string
	builtInOutput  []string
	userdefined    []UserDefinedChain
}
type TableSecurity struct {
	chains         []Chain
	builtInInput   []string
	builtInOutput  []string
	builtInForward []string
	userdefined    []UserDefinedChain
}

type Iptables struct {
	protocol Protocol
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
	ret.protocol = IPv4
	currentBlockPtr = &filterBlock
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line = strings.Trim(scanner.Text(), " \t")

		if ret.protocol != IPv6 {
			if isIPv6(line) {
				ret.protocol = IPv6
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
			ret = append(ret, Chain{name: split[0], target: split[1]})
		}
	}
	return ret
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
			rule := strings.Join(split[2:], " ")
			switch split[1] {
			case "INPUT":
				table.builtInInput = append(table.builtInInput, rule)
			case "OUTPUT":
				table.builtInOutput = append(table.builtInOutput, rule)
			case "FORWARD":
				table.builtInForward = append(table.builtInForward, rule)
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
			rule := strings.Join(split[2:], " ")
			switch split[1] {
			case "PREROUTING ":
				table.builtInPrerouting = append(table.builtInPrerouting, rule)
			case "OUTPUT":
				table.builtInOutput = append(table.builtInOutput, rule)
			case "POSTROUTING":
				table.builtInPostrouting = append(table.builtInPostrouting, rule)
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
			rule := strings.Join(split[2:], " ")
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
			rule := strings.Join(split[2:], " ")
			switch split[1] {
			case "PREROUTING":
				table.builtInPrerouting = append(table.builtInPrerouting, rule)
			case "OUTPUT":
				table.builtInOutput = append(table.builtInOutput, rule)
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
			rule := strings.Join(split[2:], " ")
			switch split[1] {
			case "INPUT":
				table.builtInInput = append(table.builtInInput, rule)
			case "OUTPUT":
				table.builtInOutput = append(table.builtInOutput, rule)
			case "FORWARD":
				table.builtInForward = append(table.builtInForward, rule)
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
