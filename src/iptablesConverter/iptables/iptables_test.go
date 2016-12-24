package iptables

import "testing"

func dumpTable(tab Iptables, t *testing.T) {
	if len(tab.filter.builtInOutput) == 0 {
		t.Errorf("Failed to read rule file")
		t.Fail()
	}

	t.Logf("Protocol: %d\n", tab.family)
	for i, chain := range tab.filter.chains {
		t.Logf("[%d] CHAIN: '%s' -> '%s'", i, chain.name, chain.target)
	}
	for i, filter := range tab.filter.builtInInput {
		t.Logf("[%d] -A INPUT -> '%s'\n", i, filter.rule)
	}
	for i, filter := range tab.filter.builtInOutput {
		t.Logf("[%d] -A OUTPUT -> '%s'\n", i, filter.rule)
	}
	for i, filter := range tab.filter.builtInForward {
		t.Logf("[%d] -A FORWARD -> '%s'\n", i, filter.rule)
	}
	for i, c := range tab.filter.userdefined {
		for j, r := range c.rules {
			t.Logf("[%d, %d] -A %s -> '%s'\n", i, j, c.chain.name, r.rule)
		}
	}
}

func TestReadv4(t *testing.T) {
	path := "/etc/iptables.rules"
	t.Logf("Reading '%s'\n", path)
	tab, err := Read(path)
	if err.msg != "" {
		t.Errorf("Error reading %s: %s:%d\n", path, err.err, err.line)
	}
	if err.err != nil {
		t.Error(err.err)
	}

	dumpTable(tab, t)
}

func TestReadv6(t *testing.T) {
	path := "/etc/ip6tables.rules"
	t.Logf("Reading '%s'\n", path)
	tab, err := Read(path)
	if err.msg != "" {
		t.Errorf("Error reading %s: %s:%d\n", path, err.err, err.line)
	}
	if err.err != nil {
		t.Error(err.err)
	}

	dumpTable(tab, t)
}
