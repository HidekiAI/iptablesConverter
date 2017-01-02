package iptables

import "testing"

func dumpTable(tab Iptables, t *testing.T) {
	if len(tab.Filter.BuiltInOutput) == 0 {
		t.Errorf("Failed to read rule file")
		t.Fail()
	}

	t.Logf("Protocol: %d\n", tab.Family)
	for i, policy := range tab.Filter.DefaultPolicies {
		t.Logf("[%d] Default chain policy: '%s' -> '%s' [%d:%d]", i, policy.ChainName, policy.Policy, policy.PacketCounter, policy.ByteCounter)
	}
	for i, filter := range tab.Filter.BuiltInInput {
		t.Logf("[%d] -A INPUT -> '%s'\n", i, filter.Rule)
	}
	for i, filter := range tab.Filter.BuiltInOutput {
		t.Logf("[%d] -A OUTPUT -> '%s'\n", i, filter.Rule)
	}
	for i, filter := range tab.Filter.BuiltInForward {
		t.Logf("[%d] -A FORWARD -> '%s'\n", i, filter.Rule)
	}
	for i, c := range tab.Filter.Userdefined {
		for j, r := range c.Rules {
			t.Logf("[%d, %d] -A %s -> '%s'\n", i, j, c.Name, r.Rule)
		}
	}
}

func TestReadv4(t *testing.T) {
	path := "iptables.rules"
	t.Logf("Reading '%s'\n", path)
	tab, err := Read(path)
	if err.Msg != "" {
		t.Errorf("Error reading %s: %s:%d\n", path, err.Err, err.Line)
	}
	if err.Err != nil {
		t.Error(err.Err)
	}

	dumpTable(tab, t)
}

func TestReadv6(t *testing.T) {
	path := "ip6tables.rules"
	t.Logf("Reading '%s'\n", path)
	tab, err := Read(path)
	if err.Msg != "" {
		t.Errorf("Error reading %s: %s:%d\n", path, err.Err, err.Line)
	}
	if err.Err != nil {
		t.Error(err.Err)
	}

	dumpTable(tab, t)
}
