package nftables

import (
	"fmt"
	"log"
	"net"
	"path/filepath"
	"reflect"
	"runtime"
)

type TLogLevel uint8

const (
	// TODO: Make the constants based on syslog instead
	CLogLevelNone       TLogLevel = 0
	CLogLevelInfo       TLogLevel = 1
	CLogLevelDebug      TLogLevel = 2
	CLogLevelVerbose    TLogLevel = 3
	CLogLevelDiagnostic TLogLevel = 4
)

// TODO: Rather than having this as constant, it may be ideal to be a variable which can be set via command line arg...
const CLogLevel = CLogLevelInfo
const tabs = "|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|:|"
const fileTabs = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t"

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

func (t TToken) FromString(s string) error {
	if s != "" {
		t = TToken(s)
		return nil
	}
	return fmt.Errorf("Empty string should not be tokenized")
}
func (t TToken) ToString() string {
	return string(t)
}

//func (tl []TToken) ToString() string {
func TokensToString(tl []TToken) string {
	retStr := ""
	for i, t := range tl {
		retStr += t.ToString()
		if i+1 < len(tl) {
			retStr += " "
		}
	}
	return retStr
}

const (
	CTokenTable   TToken = "table"
	CTokenChain   TToken = "chain"
	CTokenSC      TToken = ";"
	CTokenColon   TToken = ":"
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
	NE    *bool
	GT    *bool
	GE    *bool
	LT    *bool
	LE    *bool
}

// Address families determine the type of packets which are processed. For each address family the kernel contains so called hooks at specific stages of the packet processing paths, which invoke nftables if rules for these hooks exist.
type TAddressFamily TToken

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

type THookName TToken

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
type TTableName TToken
type TTableCommand TToken

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
type TChainName TToken
type TChainCommand TToken
type TChainType TToken

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

// Rules are constructed from two kinds of components according to a set of grammatical
// rules: expressions and statements.
//type TRule struct {
//	Policy    *TVerdict
//	Type      *TRuleType
//	Meta      *TExpressionMeta
//	Payload   *TRulePayload
//	ConnTrack *TExpressionConntrack
//	Counter   *TStatementCounter
//	Statement *TRuleStatement
//}
type TChain struct {
	// NOTE: Unlinke TChainedExpressions, TChain only requore rooted Rule instead of arrayed []interface{} list
	Rule interface{}   // chain-rule of any type (must use switch-type of 'pChain.Rule.(type)' to determine dynamically)
	Next *TChain       // chains are ordered
	Type TExprTypeInfo // Each expression has to be known of its type
}

func (pC *TChain) HasExpression() bool {
	if pC != nil {
		return (pC.Rule != nil)
	}
	return false
}
func (pC *TChain) GetTokens() []TToken {
	var retTokens []TToken
	if pC.HasExpression() {
		switch tRule := pC.Rule.(type) {
		case *TVerdict:
			//retTokens = append(retTokens, []TToken{tRule.Type.Type, TToken(*tRule)})
			retTokens = append(retTokens, GetTokens(tRule)...)
		case *TRuleType:
			retTokens = append(retTokens, GetTokens(tRule)...)
		case *TExpressionMeta:
			retTokens = append(retTokens, tRule.GetTokens()...)
		case *TRulePayload:
			retTokens = append(retTokens, tRule.GetTokens()...)
		case *TExpressionConntrack:
			retTokens = append(retTokens, tRule.GetTokens()...)
		case *TStatementCounter:
			retTokens = append(retTokens, tRule.GetTokens()...)
		case *TRuleStatement:
			retTokens = append(retTokens, tRule.GetTokens()...)
		default:
			switch tE := pC.Rule.(type) {
			case TStatementVerdict:
				retTokens = append(retTokens, GetTokens(tE)...)
			case TStatementLog:
				retTokens = append(retTokens, GetTokens(tE)...)
			case TStatementCounter:
				retTokens = append(retTokens, GetTokens(tE)...)
			case TEquate:
				retTokens = append(retTokens, GetTokens(tE)...)
			default:
				caller := ""
				// Caller(1) means the callee of this method (skip 1 stack)
				if _, f, ln, ok := runtime.Caller(1); ok {
					_, fn := filepath.Split(f)
					caller = fmt.Sprintf("%s:%d", fn, ln)
				}
				log.Panicf("%s: Unhandled type '%T' encountered (contents: '%+v')", caller, tE, tE)
			}
		}
	}
	return retTokens
}

// TChainedExpressions should be contained by struts such that each struct
// may be able to have its own Interface such that methods:
//		func (expr *TExpressionHeaderUdpLite) HasExpression() bool
//		func (expr *TExpressionHeaderUdpLite) GetTokens() []TToken
// can be implemented specific to each statement types.  Also, because the
// switch-type needs to distinguish its uniqueness, you will have to make sure
// to create a distinct type (for example, if a struct has signature as follows:
//	type MyStruct struct {
//		Foo string
//		Bar string
//	}
// To distinguish the differences of two strings, it will have to be typed
//	type TFoo string
//	type TBar string
//	type MyStruct struct {
//		Expr TChainedExpression
//	}
// And implementations would be:
//	switch t := mystructi.Expression.(type) {
//		case TFoo, *TFoo, []TFoo, []*TFoo:
//			// do something with t.*
//		case TBar, *TBar, []TBar, []*TBar:
//			// do something with t.*
//		default:
//			log.Panicf("Unhandled type '%T'", t)
//	}
type TExprTypeInfo struct {
	Type    TToken // i.e. 'ct', 'meta', etc
	SubType TToken // sub-type of an expression, i.e. for 'ct mark', 'mark' is the Type for conntrack 'ct' expression
	Depth   uint16 // for debug purpose
}

func (eti TExprTypeInfo) ToString() string {
	return eti.Type.ToString()
}
func (eti TExprTypeInfo) FromString(s string) error {
	return eti.Type.FromString(s)
}
func (pType *TExprTypeInfo) Set(t TToken, s TToken, d uint16) {
	if pType != nil {
		pType.Type = t
		pType.SubType = s
		pType.Depth = d
	}
}
func (pType *TExprTypeInfo) SetSubType(s TToken) {
	if pType != nil {
		pType.SubType = s
	}
}

type TTokenExpr struct {
	Expression interface{}
	Type       TExprTypeInfo
	token      TToken
}

func (pExpr *TTokenExpr) ToString() string {
	if (pExpr != nil) && (pExpr.Expression != nil) {
		return string(pExpr.token)
	}
	return ""
}
func GetTokens(pExpr interface{}) []TToken {
	if cast, ok := pExpr.(*TTokenExpr); ok {
		return cast.GetTokens()
	}
	return nil
}
func (pExpr *TTokenExpr) GetTokens() []TToken {
	ret := []TToken{}
	if (pExpr != nil) && (pExpr.Expression != nil) {
		ret = append(ret, pExpr.token)
	}
	return ret
}
func (pExpr *TTokenExpr) SetType(t TToken, d uint16) {
	if (pExpr != nil) && (pExpr.Expression != nil) {
		pExpr.Type.Set(t, "", d)
	}
}
func (pExpr *TTokenExpr) SetSubType(s TToken) {
	if (pExpr != nil) && (pExpr.Expression != nil) {
		pExpr.Type.SetSubType(s)
	}
}

type TChainedExpressions struct {
	// chain-rule of any type (must use switch-type of 'pChain.Rule.(type)' to determine dynamically)
	Expressions []interface{} // Expression are sequentially ordered chains (i.e. TEquate -> Cpu -> TLog ->  TVerdict)
	Type        TExprTypeInfo
	tokens      []TToken // Mainly for debug purpose, each line of rules in a TTable, it is array so it can be tokenized (i.e. differences between "This is a string" as single token versus 4 tokens)
}

func (pExpression *TChainedExpressions) GetNext() func() interface{} {
	i := -1
	if (pExpression != nil) && (pExpression.Expressions != nil) {
		return func() interface{} {
			i = i + 1
			if len(pExpression.Expressions) > i {
				return pExpression.Expressions[i]
			}
			i = -1
			return nil
		}
	}
	return nil
}
func (pExpression *TChainedExpressions) GetType() TExprTypeInfo {
	if pExpression != nil {
		return pExpression.Type
	}
	return TExprTypeInfo{}
}
func (pExpression *TChainedExpressions) SetType(t TToken, d uint16) {
	if pExpression != nil {
		pExpression.Type.Set(t, "", d)
	}
}
func (pExpression *TChainedExpressions) SetSubType(s TToken) {
	if pExpression != nil {
		pExpression.Type.SetSubType(s)
	}
}
func (pExpression *TChainedExpressions) GetTypeString() string {
	return pExpression.GetType().ToString()
}
func (pExpression *TChainedExpressions) GetTokens() ([]TToken, error) {
	if pExpression != nil {
		return pExpression.tokens, nil
	}
	return []TToken{}, fmt.Errorf("Expression pointer must not be nil")
}
func (pExpression *TChainedExpressions) TokensToString() string {
	tl, err := pExpression.GetTokens()
	if err == nil {
		return TokensToString(tl)
	}
	return ""
}
func (pExpression *TChainedExpressions) ToString() string {
	return pExpression.TokensToString() // this is same as above
}
func (thisToken *TChainedExpressions) AppendToken(token TToken) {
	thisToken.AppendTokens([]TToken{token})
}
func (thisToken *TChainedExpressions) AppendTokens(tokens []TToken) {
	if (thisToken != nil) && (len(tokens) > 0) {
		thisToken.tokens = append(thisToken.tokens, tokens...)

		if CLogLevel >= CLogLevelDiagnostic {
			caller := ""
			// Caller(1) means the callee of this method (skip 1 stack)
			if _, f, ln, ok := runtime.Caller(1); ok {
				_, fn := filepath.Split(f)
				caller = fmt.Sprintf("%s:%d", fn, ln)
			}
			log.Printf("\t\t>> %s: TChainedExpressions.Append(%v) -> %v", caller, tokens, thisToken.tokens)
		}
	}
}
func (pExpression *TChainedExpressions) Append(iface interface{}) error {
	if (pExpression != nil) && (iface != nil) {
		pExpression.Expressions = append(pExpression.Expressions, iface)
		return nil
	}
	return fmt.Errorf("TChainedExpressions is nil")
}
func (pExpression *TChainedExpressions) GetExpressions() ([]interface{}, error) {
	if pExpression != nil {
		return pExpression.Expressions, nil
	}
	return nil, fmt.Errorf("Expression pointer must not be nil")
}
func (pExpression *TChainedExpressions) GetTypeInterface(i int) interface{} {
	if (pExpression != nil) && (len(pExpression.Expressions) > i) {
		return reflect.TypeOf(pExpression.Expressions[i])
	}
	return nil
}
func (pExpression *TChainedExpressions) ParseTailChains(rule *TTextStatement, iTokenIndex uint16) error {
	tokens, _, _, vcError := rule.getNextToken(iTokenIndex, 1, true)
	if vcError == nil {
		done := false
		for done == false {
			// verdits usually goes last, so always check 'counter' token first
			if rule.isCounterRule(iTokenIndex) {
				pExpression.AppendToken(tokens[0])
				if cntr, cntrErr := rule.parseCounter(iTokenIndex); cntrErr == nil {
					pExpression.Append(cntr)
					// skip forward to next token
					tokens, iTokenIndex, rule, cntrErr = rule.getNextToken(iTokenIndex, 1, true)
					if (cntrErr != nil) || (rule == nil) {
						done = true
						break
					}
				}
			} else if rule.isVerdict(iTokenIndex) {
				pExpression.AppendToken(tokens[0])
				if vrdct, vErr := rule.parseVerdict(iTokenIndex); vErr == nil {
					pExpression.Append(vrdct)
					// skip forward to next token
					tokens, iTokenIndex, rule, vErr = rule.getNextToken(iTokenIndex, 1, true)
					if (vErr != nil) || (rule == nil) {
						done = true
						break
					}
				}
			} else {
				done = true
				break
			}
		}
	}
	return vcError
}

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
	Device    TToken
	Priority  Tpriority
	Policy    *TVerdict // type can have default policy

	Type   TExprTypeInfo
	Tokens []TToken
}

func (pRule *TRuleType) ToString() string {
	if pRule != nil {
		return TokensToString(pRule.Tokens)
	}
	return ""
}
func (pRule *TRuleType) AppendTokens(tl []TToken) {
	if (pRule != nil) && (len(tl) > 0) {
		pRule.Tokens = append(pRule.Tokens, tl...)
	}
}

type TRulePayload struct {
	Expr TChainedExpressions
	//Ether   *TExpressionHeaderEther
	//Vlan    *TExpressionHeaderVlan
	//Arp     *TExpressionHeaderArp
	//Ip      *TExpressionHeaderIpv4
	//Ip6     *TExpressionHeaderIpv6
	//Tcp     *TExpressionHeaderTcp
	//Udp     *TExpressionHeaderUdp
	//UdpLite *TExpressionHeaderUdpLite
	//Sctp    *TExpressionHeaderSctp
	//Dccp    *TExpressionHeaderDccp
	//Ah      *TExpressionHeaderAH
	//Esp     *TExpressionHeaderESP
	//IpComp  *TExpressionHeaderIpcomp
	//Ip6Ext  *TExpressionHeaderIpv6Ext
	//Icmp    *TICMP
	//Icmpv6  *TICMPv6
	//Dst     *TMatchDST
	//Frag    *TFrag
	//Hbh     *THbh
	//Mh      *TMH
	//Rt      *TRouting
}

func (payload *TRulePayload) HasExpression() bool {
	if payload != nil {
		return (payload.Expr.Expressions != nil) && (len(payload.Expr.Expressions) > 0)
	}
	return false
	//if payload == nil {
	//	return false
	//}
	//return (payload.Ether != nil || payload.Vlan != nil || payload.Arp != nil || payload.Ip != nil || payload.Ip6 != nil ||
	//	payload.Tcp != nil || payload.Udp != nil || payload.UdpLite != nil || payload.Sctp != nil || payload.Dccp != nil ||
	//	payload.Ah != nil || payload.Esp != nil || payload.IpComp != nil || payload.Ip6Ext != nil || payload.Icmp != nil ||
	//	payload.Icmpv6 != nil || payload.Dst != nil || payload.Frag != nil || payload.Hbh != nil || payload.Mh != nil || payload.Rt != nil)
}
func (payload *TRulePayload) GetTokens() []TToken {
	var ret []TToken
	if payload == nil {
		return ret
	}
	if payload.HasExpression() {
		for _, p := range payload.Expr.Expressions {
			switch t := p.(type) {
			case *TExpressionHeaderEther:
				ret = append(ret, t.GetTokens()...)
			case *TExpressionHeaderVlan:
				ret = append(ret, t.GetTokens()...)
			case *TExpressionHeaderArp:
				ret = append(ret, t.GetTokens()...)
			case *TExpressionHeaderIpv4:
				ret = append(ret, t.GetTokens()...)
			case *TExpressionHeaderIpv6:
				ret = append(ret, t.GetTokens()...)
			case *TExpressionHeaderTcp:
				ret = append(ret, t.GetTokens()...)
			case *TExpressionHeaderUdp:
				ret = append(ret, t.GetTokens()...)
			case *TExpressionHeaderUdpLite:
				ret = append(ret, t.GetTokens()...)
			case *TExpressionHeaderSctp:
				ret = append(ret, t.GetTokens()...)
			case *TExpressionHeaderDccp:
				ret = append(ret, t.GetTokens()...)
			case *TExpressionHeaderAH:
				ret = append(ret, t.GetTokens()...)
			case *TExpressionHeaderESP:
				ret = append(ret, t.GetTokens()...)
			case *TExpressionHeaderIpcomp:
				ret = append(ret, t.GetTokens()...)
			case *TExpressionHeaderIpv6Ext:
				ret = append(ret, t.GetTokens()...)
			case *TICMP:
				ret = append(ret, t.GetTokens()...)
			case *TICMPv6:
				ret = append(ret, t.GetTokens()...)
			case *TMatchDST:
				ret = append(ret, t.GetTokens()...)
			case *TFrag:
				ret = append(ret, t.GetTokens()...)
			case *THbh:
				ret = append(ret, t.GetTokens()...)
			case *TMH:
				ret = append(ret, t.GetTokens()...)
			case *TRouting:
				ret = append(ret, t.GetTokens()...)
			default:
				switch tE := p.(type) {
				case TStatementVerdict:
					ret = append(ret, GetTokens(tE)...)
				case TStatementLog:
					ret = append(ret, GetTokens(tE)...)
				case TStatementCounter:
					ret = append(ret, GetTokens(tE)...)
				case TEquate:
					ret = append(ret, GetTokens(tE)...)
				default:
					caller := ""
					// Caller(1) means the callee of this method (skip 1 stack)
					if _, f, ln, ok := runtime.Caller(1); ok {
						_, fn := filepath.Split(f)
						caller = fmt.Sprintf("%s:%d", fn, ln)
					}
					log.Panicf("%s: Unhandled type '%T' encountered (contents: '%+v')", caller, tE, tE)
				}
			}
		}
	}
	return ret
}

type TRuleStatement struct {
	Expr TChainedExpressions
	//Verdict *TStatementVerdict
	//Log     *TStatementLog
	//Reject  *TStatementReject
	//Counter *TStatementCounter
	//Meta    *TExpressionMeta
	//Limit   *TStatementLimit
	//Nat     *TStatementNat
	//Queue   *TStatementQueue
}

func (expr *TRuleStatement) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
	//if expr == nil {
	//	return false
	//}
	//return (expr.Verdict != nil || expr.Log != nil || expr.Reject != nil ||
	//	expr.Counter != nil || expr.Meta != nil || expr.Limit != nil ||
	//	expr.Nat != nil || expr.Queue != nil)
}
func (expr *TRuleStatement) GetTokens() []TToken {
	var ret []TToken
	if expr == nil {
		return ret
	}
	if expr.HasExpression() {
		for _, e := range expr.Expr.Expressions {
			switch t := e.(type) {
			case *TStatementVerdict:
				ret = append(ret, expr.GetTokens()...)
			case *TStatementLog:
				ret = append(ret, expr.GetTokens()...)
			case *TStatementReject:
				ret = append(ret, expr.GetTokens()...)
			case *TStatementCounter:
				ret = append(ret, expr.GetTokens()...)
			case *TExpressionMeta:
				ret = append(ret, expr.GetTokens()...)
			case *TStatementLimit:
				ret = append(ret, expr.GetTokens()...)
			case *TStatementNat:
				ret = append(ret, expr.GetTokens()...)
			case *TStatementQueue:
				ret = append(ret, expr.GetTokens()...)
			default:
				switch tE := e.(type) {
				case TStatementVerdict:
					ret = append(ret, GetTokens(tE)...)
				case TStatementLog:
					ret = append(ret, GetTokens(tE)...)
				case TStatementCounter:
					ret = append(ret, GetTokens(tE)...)
				case TEquate:
					ret = append(ret, GetTokens(tE)...)
				default:
					caller := ""
					// Caller(1) means the callee of this method (skip 1 stack)
					if _, f, ln, ok := runtime.Caller(1); ok {
						_, fn := filepath.Split(f)
						caller = fmt.Sprintf("%s:%d", fn, ln)
					}
					log.Panicf("%s: Unhandled type '%T' encountered (contents: '%+v')", caller, tE, tE)
				}
			}
		}
	}
	return ret
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
type Tnfproto TToken
type Tprotocol TToken
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
	Num   *int
	Alias *TToken
	Range *TMinMax
}
type TUInt32OrAlias struct {
	Num   *uint32
	Alias *TToken
	Range *TMinMaxU32
}
type TInt8OrAlias struct {
	Num   *int8
	Alias *TToken
	Range *TMinMax8
}
type TUInt8OrAlias struct {
	Num   *uint8
	Alias *TToken
	Range *TMinMaxU8
}
type TInt16OrAlias struct {
	Num   *int16
	Alias *TToken
	Range *TMinMax16
}
type TUInt16OrAlias struct {
	Num   *uint16
	Alias *TToken
	Range *TMinMaxU16
}

type TVerdict TTokenExpr
type TPort uint32

// inet_service
type Tinetservice struct {
	Port        *[2]TPort  // i.e. '22' or '8000-8001', for lists like '{22, 80, 443, 8000-8001}', do []Tinetservice
	ServicePort *[2]TToken // i.e. 'ssh' or 'ssh-telnet', for lists like '{ssh, http, https, 8000-8001}', do array
}
type Tinetproto struct { // inet_proto
	Range *TMinMaxU32 // can be either single number (i.e. {22, -1}) or ranged paired (i.e. {1024-2048})
	Alias *TToken     // in some cases it can be a list (i.e. {esp, udp, ah, comp}) - for lists of alias, make sure do to do []Tinetproto
}

// vmap: i.e. 'tcp dport vmap { 22 : accept, 23 : drop }'
type TVMap struct {
	Port        *TPort
	ServicePort *TToken
	Verdict     TVerdict
}

// ID (i.e. uid or gid) can be either int or string
// i.e. id=bin, root, daemon
// it can also be range based (i.e. '2000-2005')
type TID struct {
	IDByName *[]TToken // can be CSV (i.e. {bin, root, daemon}
	ID       *[2]int   // range based, but if just single, it is {n, -1} - ID=0 is root, -1 indicates unset
}

// Nftables is just a container map of tables where the KEY is a unique
// dotted namespace (family.tableName) for quicker lookup
type TUniqueTableName string // dotted table name such as "ip.filter", "ip6.nat" so that if there are "ip6" and "ip" family to table "filter", we can distinguish it
type Nftables struct {
	Tables map[TUniqueTableName]*TTable // key: table name (i.e. "ip.filter", "ip6.filter")
	//sync.RWMutex	// see https://blog.golang.org/go-maps-in-action in terms of concurrency issue with maps
}

func init() {
	log.SetFlags(log.Lshortfile)
}
