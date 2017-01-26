package nftables

import "testing"

//import "strconv"
import "fmt"

func TestAddTableSuccess(t *testing.T) {
	var nft Nftables
	addedT := nft.AddTable(CAddressFamilyIP, "filter")
	if addedT == nil {
		t.Fail()
	}
	found := nft.FindTable(CAddressFamilyIP, "filter")
	if found == nil {
		t.Fail()
	}
}

func TestAddTableNotFound(t *testing.T) {
	var nft Nftables
	addedT := nft.AddTable(CAddressFamilyIP6, "filter")
	if addedT == nil {
		t.Fail()
	}
	// Should not find "filter" for it's not unique (i.e. "ip.filter" vs "ip6.filter")
	found := nft.FindTable(CAddressFamilyIP, "filter")
	if found != nil {
		t.Fail()
	}
}

func TestFindTableNoAdd(t *testing.T) {
	var nft Nftables
	found := nft.FindTable(CAddressFamilyIP6, "filter")
	if found != nil {
		t.Errorf("Found table in an empty Nftables\n")
		t.Fail()
	}
}

func TestStripCommentAndTokenizing(t *testing.T) {
	e := "   element1, element2,min - max, element3 key1:value key2 : value2 {set1, set2,set3}"
	eexp := "element1,element2,min-max,element3 key1:value key2:value2 { set1,set2,set3 }" // parser will join the comma separated tokens into single token

	s := `this line has 'quoted #comments' followed by "double-quoted #comment's with sinqle quote in it" here comes the hash`

	swc := e + " " + s + ` # <-- and here's the end`
	// strip it it'll do parsing as well as tokenizing, all in one
	ss := stripComment(swc)

	expected := eexp + " " + s

	t.Logf("Original: '%s'\n", swc)
	t.Logf("Stripped: '%s'\n", ss)
	t.Logf("Expected: '%s'\n", expected)
	if ss != expected {
		t.Fail()
	}
}

func testPrintTextBlockRecursive(t *testing.T, tsPtr *TTextStatement, si int) {
	const tabs = "|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|"
	if tsPtr != nil {
		outStr := fmt.Sprintf("%3d:(%16p:%16p)%s", si, tsPtr.Parent, tsPtr, tabs[:tsPtr.Depth])
		if len(tsPtr.Tokens) > 0 {
			for _, t := range tsPtr.Tokens {
				outStr += t + " "
			}
		}
		t.Log(outStr)

		// Now dump TTextSTatement.SubStatement[]
		if len(tsPtr.SubStatement) > 0 {
			for _, ss := range tsPtr.SubStatement {
				testPrintTextBlockRecursive(t, ss, si)
			}
		}
	}
}

const testData = `
# filter
table ip filter {
	chain input { # input chain
		type filter hook input priority 0; policy drop;# sticky semi-colon and comment edge-case
		ct state {established, related} accept counter comment "expressions follwoing the {} block to associate it to THIS line"
		ct state invalid counter drop comment "a line with ; in it"
		iifname lo accept comment "accept loopback"
		iifname != lo ip daddr 127.0.0.1/8 counter drop comment "don't worry, #comments cannot have double quotes inside it"
		ip protocol icmp counter accept comment "comment has ' and # in it"
		tcp dport 22 counter accept comment "accept ssh"
		counter comment "count dropped packets"
	}

	chain output {
		type filter hook output priority 0; policy accept;		counter comment "comment has a ' and ; in it";
		;
		# accept traffic originated from us
		ct state { established, related} accept
		# alternatively:
		#ct state established accept
		#ct state related accept

		# accept any localhost traffic
		iif lo accept

		# meta tests
		skuid != 2001-2005
		meta skgid gt 2000
		cpu {2-3, 5-7}
		meta mark set 0xffffffc8 xor 0x18
		l4proto != 233
		meta nfproto {ipv4, ipv6}
		meta length > 1000

		tcp dport ssh counter accept

		# count and drop any other traffic
		counter drop

		counter log drop
	}

	# using '\' to do continuations
	chain forward {
		type filter hook forward \
			priority 0; policy drop;
		counter comment "count dropped packets";
		{some made up { nested statement } in one line}
		ct state related,established accept
	}

	# all in one line, with ';' right before '}' and adding {} to fool the parser }
	chain nat{type filter hook nat priority 0;policy drop;}
}
# ip6 filter
table ip6 filter {
}`

func TestTextBlock(t *testing.T) {
	tsList := MakeStatements(testData)
	for i, ts := range tsList {
		testPrintTextBlockRecursive(t, ts, i)
	}
}

func TestDeserializeFromFile(t *testing.T) {
	path := "nft.rules"
	nft := Read(path)
	t.Logf("%+v", nft)
	// assume the rules files only has three tables (ip, ip6, and inet)
	if len(nft.Tables) != 3 {
		t.Fail()
	}
}
