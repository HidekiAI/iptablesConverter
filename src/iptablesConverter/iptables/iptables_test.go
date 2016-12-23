package iptables

import "testing"

func TestReadv4(t *testing.T) {
	path := "/etc/iptables.rules"
	Read(path)
}
func TestReadv6(t *testing.T) {
	path := "/etc/ip6tables.rules"
	Read(path)
}
