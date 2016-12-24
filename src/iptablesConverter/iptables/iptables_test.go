package iptables

import (
    "reflect"
    "testing"
)

func TestReadv4(t *testing.T) {
    path := "/etc/iptables.rules"
    t.Logf("Reading '%s'\n", path)
    tab := Read(path)
    if len(tab.filter.builtInOutput) == 0 {
        t.Errorf("Failed to read %s", path)
        t.Fail()
    }
    t.Logf("Protocol: %d\n", tab.protocol)
    for i, chain := range tab.filter.chains {
        t.Logf("[%d] CHAIN: '%s' -> '%s'", i, chain.name, chain.target)
    }
    for i, filter := range tab.filter.builtInInput {
        t.Logf("[%d] -A INPUT -> '%s'\n", i, filter)
    }
    for i, filter := range tab.filter.builtInOutput {
        t.Logf("[%d] -A OUTPUT -> '%s'\n", i, filter)
    }
    for i, filter := range tab.filter.builtInForward {
        t.Logf("[%d] -A FORWARD -> '%s'\n", i, filter)
    }
    for i, c := range tab.filter.userdefined {
        for j, r := range c.rules {
            t.Logf("[%d, %d] -A %s -> '%s'\n", i, j, c.chain.name, r)
        }
    }
}
func TestReadv6(t *testing.T) {
    path := "/etc/ip6tables.rules"
    t.Log(Read(path))
}

func TestRead(t *testing.T) {
    type args struct {
        path string
    }
    tests := []struct {
        name string
        args args
        want Iptables
    }{
    // TODO: Add test cases.
    //tests = append(tests, struct{name: "ReadIPv4", args.path : "/etc/iptables.rules" })
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := Read(tt.args.path); !reflect.DeepEqual(got, tt.want) {
                t.Errorf("Read() = %v, want %v", got, tt.want)
            }
        })
    }
}

func Test_isIPv6(t *testing.T) {
    type args struct {
        line string
    }
    tests := []struct {
        name string
        args args
        want bool
    }{
    // TODO: Add test cases.
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := isIPv6(tt.args.line); got != tt.want {
                t.Errorf("isIPv6() = %v, want %v", got, tt.want)
            }
        })
    }
}

func Test_findChains(t *testing.T) {
    type args struct {
        lines []string
    }
    tests := []struct {
        name string
        args args
        want []Chain
    }{
    // TODO: Add test cases.
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := findChains(tt.args.lines); !reflect.DeepEqual(got, tt.want) {
                t.Errorf("findChains() = %v, want %v", got, tt.want)
            }
        })
    }
}

func Test_parseFilter(t *testing.T) {
    type args struct {
        lines []string
    }
    tests := []struct {
        name string
        args args
        want TableFilter
    }{
    // TODO: Add test cases.
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := parseFilter(tt.args.lines); !reflect.DeepEqual(got, tt.want) {
                t.Errorf("parseFilter() = %v, want %v", got, tt.want)
            }
        })
    }
}

func Test_parseNat(t *testing.T) {
    type args struct {
        lines []string
    }
    tests := []struct {
        name string
        args args
        want TableNat
    }{
    // TODO: Add test cases.
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := parseNat(tt.args.lines); !reflect.DeepEqual(got, tt.want) {
                t.Errorf("parseNat() = %v, want %v", got, tt.want)
            }
        })
    }
}

func Test_parseMangle(t *testing.T) {
    type args struct {
        lines []string
    }
    tests := []struct {
        name string
        args args
        want TableMangle
    }{
    // TODO: Add test cases.
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := parseMangle(tt.args.lines); !reflect.DeepEqual(got, tt.want) {
                t.Errorf("parseMangle() = %v, want %v", got, tt.want)
            }
        })
    }
}

func Test_parseRaw(t *testing.T) {
    type args struct {
        lines []string
    }
    tests := []struct {
        name string
        args args
        want TableRaw
    }{
    // TODO: Add test cases.
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := parseRaw(tt.args.lines); !reflect.DeepEqual(got, tt.want) {
                t.Errorf("parseRaw() = %v, want %v", got, tt.want)
            }
        })
    }
}

func Test_parseSecurity(t *testing.T) {
    type args struct {
        lines []string
    }
    tests := []struct {
        name string
        args args
        want TableSecurity
    }{
    // TODO: Add test cases.
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            if got := parseSecurity(tt.args.lines); !reflect.DeepEqual(got, tt.want) {
                t.Errorf("parseSecurity() = %v, want %v", got, tt.want)
            }
        })
    }
}
