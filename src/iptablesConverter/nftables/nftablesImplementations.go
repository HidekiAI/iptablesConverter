package nftables

import (
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

//
func Read(path string) Nftables {
	ret := Nftables{}
	// hopefully, an nftable rule files do not exceed RAM _AND_ doesn't have INCLUDE statement
	// we'll revisit the INCLUDE injection later...
	file, openErr := os.Open(path)
	if openErr != nil {
		log.Panic(openErr)
	}
	defer file.Close()

	buffer := make([]byte, 1024*1024*16)
	nb, rErr := file.Read(buffer)
	if rErr != nil || nb > len(buffer) {
		log.Panicf("Increase the buffer size to more than %d bytes", nb)
	}
	tables := MakeStatements(string(buffer)) // bad bad bad!
	// deserialize []*TTextStatement
	//for _, ts := range tables {
	//	ts.deserializeRecursive(&ret, nil, CAddressFamilyUndefined, nil)
	//}
	for _, ts := range tables {
		ts.deserialize(&ret)
	}
	return ret
}

// As a parent, it should deserialize itself and its children; should be agnostic of its siblings
func (pThisStatement *TTextStatement) deserializeRecursive(nft *Nftables, pCurrentTable *TTable, caf TAddressFamily, pCurrentChain *TChain) {
	// first, parse the tokens - NOTE that what we are interested in are
	// are statements that have AT LEAST 2 tokens.  Statements which only
	// have one is usually comments ("#"), beginning of statements ("{"),
	// closing of statements ("}"), or new line (";").  Rest are usually
	// based on two or more (i.e. 'table INPUT')
	if len(pThisStatement.Tokens) > 0 {
		if caf == CAddressFamilyUndefined {
			// assume default
			caf = CAddressFamilyIP
		}

		token := TToken(strings.ToLower(strings.TrimSpace(pThisStatement.Tokens[0])))
		switch token {
		case CTokenTable:
			sr := stripRule(pThisStatement.Tokens)
			t := parseTable(sr)
			pCurrentTable = nft.AddTable(t.Family, t.Name)
			caf = t.Family

		case CTokenChain:
			if pCurrentTable == nil {
				log.Panicf("Unable to deal with nil Table for tokens:\n\t%+v (len: %d)\n\n", pThisStatement.Tokens, len(pThisStatement.Tokens))
			}
			sr := stripRule(pThisStatement.Tokens)
			cn, _ := parseChain(sr)
			pCurrentChain = pCurrentTable.RegisterChain(cn)

		case CTokenSC, CTokenOB, CTokenCB, CTokenHash, "":
			// do nothing

		default:
			// if it is not 'table' or 'chain' tokens, it must be rules to the TChain
			if pCurrentTable == nil {
				log.Panicf("Unable to deal with nil Table for tokens:\n\t%+v (len: %d)\n\n", pThisStatement.Tokens, len(pThisStatement.Tokens))
			}
			if pCurrentChain == nil {
				log.Panicf("Unable to deal with nil Chain for tokens:\n\t%+v (len: %d)\n\n", pThisStatement.Tokens, len(pThisStatement.Tokens))
			}
			added := pCurrentChain.ChainRule(CRuleCommandAdd, pThisStatement)
			if added == false {
				log.Panicf("Unable to add chain rule '%+v'", pThisStatement.Tokens)
			}
		}
	}

	// next, parse all statements for the token
	for _, tss := range pThisStatement.SubStatement {
		tss.deserializeRecursive(nft, pCurrentTable, caf, pCurrentChain)
	}
}

// this method does not recurse
func (pThisStatement *TTextStatement) deserialize(nft *Nftables) {
	if len(pThisStatement.Tokens) == 0 {
		return
	}

	var pCurrentTable *TTable
	tToken := TToken(strings.ToLower(strings.TrimSpace(pThisStatement.Tokens[0])))
	switch tToken {
	case CTokenTable:
		sr := stripRule(pThisStatement.Tokens)
		t := parseTable(sr)
		pCurrentTable = nft.AddTable(t.Family, t.Name)

	case CTokenSC, CTokenOB, CTokenCB, CTokenHash, "":
		// do nothing

	default:
		log.Panicf("Encountered non-Table token '%s' in table loop (%+v)", tToken, pThisStatement)
	}

	// before we walk the chains, make sure we have a table now
	if pCurrentTable == nil {
		log.Panicf("Unable to deal with nil Table")
	}
	if logLevel > 0 {
		log.Printf("Table '%s' has %d chains", pCurrentTable.Name, len(pThisStatement.SubStatement))
	}
	// walk each series of chains
	for _, currChain := range pThisStatement.SubStatement {
		var pCurrentChain *TChain
		chainName := TChainName("")
		if len(currChain.Tokens) == 0 {
			continue
		}

		cToken := TToken(strings.ToLower(strings.TrimSpace(currChain.Tokens[0])))
		switch cToken {
		case CTokenTable:
			log.Panicf("Cannot have 'table' withinside 'chain' (%+v)", currChain)

		case CTokenChain:
			if pCurrentTable == nil {
				log.Panicf("Unable to deal with nil Table for tokens:\n\t%+v (len: %d)\n\n", currChain.Tokens, len(currChain.Tokens))
			}
			sr := stripRule(currChain.Tokens)
			chainName, _ = parseChain(sr)
			pCurrentChain = pCurrentTable.RegisterChain(chainName)

		case CTokenSC, CTokenOB, CTokenCB, CTokenHash, "":
			// do nothing
			continue

		default:
			log.Panicf("Encountered non-Chain rules token '%s' in chain loop (%+v)", cToken, currChain)
		}

		// before we parse the chain rules, make sure we have the chain to associate it with
		if pCurrentChain == nil {
			log.Panicf("Unable to deal with nil Chain")
		}
		if logLevel > 0 {
			log.Printf("\t\tChain '%s' (of Table '%s') has %d chain rules", chainName, pCurrentTable.Name, len(currChain.SubStatement))
		}
		for its, ts := range currChain.SubStatement {
			haveToken, _, tokens, currentRule := getNextToken(ts, 0, 1)
			if haveToken == false {
				//log.Panicf("Unable to find next token - %+v at index=%d", ts, its)
				continue
			}
			if logLevel > 0 {
				log.Printf("\t\t\t%2d:%s%+v(Child Count:%d)\t\t\t\tcurrentRule=%12p:ts=%12p", its, tabs[:ts.Depth], ts.Tokens, len(ts.SubStatement), currentRule, ts)
			}
			// first, parse the tokens - NOTE that what we are interested in are
			// statements that have AT LEAST 2 tokens.  Statements which only
			// have one is usually comments ("#"), beginning of statements ("{"),
			// closing of statements ("}"), or new line (";").  Rest are usually
			// based on two or more (i.e. 'table INPUT')
			if len(ts.Tokens) == 0 {
				continue
			}
			if ts.Depth != currChain.Depth {
				// all sub statements that are of deeper depths *should have* been processed already
				continue
			}
			if currentRule == nil {
				log.Panicf("There are no next rules to be processed")
			}

			switch tokens[0] {
			case CTokenTable:
				log.Panicf("Cannot have 'table' withinside 'chain' (%+v) %12p", ts, currentRule)

			case CTokenChain:
				log.Panicf("Cannot have 'chain' withinside 'chain' (%+v) %12p", ts, currentRule)

			case CTokenSC, CTokenOB, CTokenCB, CTokenHash, "":
				// do nothing
				continue

			default:
				// if it is not 'table' or 'chain' tokens, it must be rules to the TChain
				added := pCurrentChain.ChainRule(CRuleCommandAdd, currentRule)
				if added == false {
					log.Panicf("Unable to add chain rule '%+v'", ts.Tokens)
				}
			}
		} // ts
	} // current chain
}

func stripRule(slist []string) []TToken {
	var sr []TToken
	for _, s := range slist {
		if s == "{" || s == "}" || s == ";" {
			continue
		}
		sr = append(sr, TToken(s))
	}
	return sr
}

// Ret parm1[bool] : true if next token found
// Ret parm2[uint16] : next token index (relative to next TTextStatement)
// Ret parm3[[]TToken] : if parm1==true, the token that was found (array size based on expectedTokens)
// Ret parm4[*TTextStatement] : next statement to reference (see next token index parm2)
func getNextToken(rule *TTextStatement, iTokenIndex uint16, expectedTokens uint16) (bool, uint16, []TToken, *TTextStatement) {
	haveNextToken := false
	if rule == nil {
		//log.Panicf("Tokens cannot be extracted from rule==nil")
		return false, 0, nil, nil
	}
	currentRule := rule
	tokens := stripRule(currentRule.Tokens)
	if len(tokens) == 0 || expectedTokens == 0 {
		return false, 0, nil, nil
	}
	// pull as much tokens we can (up to expectedTokens count)
	var nextIndex uint16 = iTokenIndex
	var retTokenList []TToken = []TToken{}
	for i := iTokenIndex; int(i) < len(tokens) && i < expectedTokens; i++ {
		retTokenList = append(retTokenList, tokens[i])
		nextIndex = uint16(i)
	}

	// first try the ideal case where iTokenIndex is in range and there is next valid index
	if len(tokens) < int(expectedTokens) {
		// cannot find next token, see if there are any children
		tokens = []TToken{}
		nextIndex = 0
		currentRule = nil
		if (rule.SubStatement != nil) && (len(rule.SubStatement) > 0) {
			// assume that every statement has AT LEAST ONE token, so no take the first sub-statement
			currentRule = rule.SubStatement[0]
			tokens = stripRule(currentRule.Tokens)
			for i := iTokenIndex; int(i) < len(tokens) && i < expectedTokens; i++ {
				retTokenList = append(retTokenList, tokens[i])
				nextIndex = uint16(i)
			}
		}
	}

	// determine next index
	if int(iTokenIndex+1) < len(tokens) {
		nextIndex = iTokenIndex + 1
	} else {
		// there is no next on current statement, so see if there are any children
		nextIndex = 0
		currentRule = nil
		if (rule.SubStatement != nil) && (len(rule.SubStatement) > 0) {
			// assume that every statement has AT LEAST ONE token, so no take the first sub-statement
			currentRule = rule.SubStatement[0]
		}
	}
	// special case, where parent has a sibling with depth that is deeper than current
	if currentRule == nil {
		if rule.Parent != nil && rule.Parent.Parent != nil {
			for is, s := range rule.Parent.Parent.SubStatement {
				if s == rule.Parent {
					if len(rule.Parent.Parent.SubStatement) > is+1 {
						n := rule.Parent.Parent.SubStatement[is+1]
						if rule.Depth == n.Depth {
							// we've found deeper depth than current, we can treat it as a child
							currentRule = n
							nextIndex = 0
						}
					}
					break
				}
			}
		}
	}
	haveNextToken = len(retTokenList) == int(expectedTokens)

	if logLevel > 2 {
		log.Printf("\tRequest:%d - HaveNextToken:%v, nextIndex:%d, next Token:'%v', Rule:%v", iTokenIndex, haveNextToken, nextIndex, tokens, currentRule)
	}
	return haveNextToken, nextIndex, retTokenList, currentRule
}

func parseEquates(t TToken) (bool, TEquate) {
	isEq := false
	var e TEquate
	switch t {
	case CTokenNE:
		e.NE = true
		isEq = true
	case CTokenGT:
		e.GT = true
		isEq = true
	case CTokengt:
		e.GT = true
		isEq = true
	case CTokenGE:
		e.GE = true
		isEq = true
	case CTokenLT:
		e.LT = true
		isEq = true
	case CTokenlt:
		e.LT = true
		isEq = true
	case CTokenLE:
		e.LE = true
		isEq = true
	case CTokeneq:
		// do nothing, it is default equates
	}

	return isEq, e
}

// Examples:
//	meta mark 0x4
//	meta mark 0x00000032
//	meta mark and 0x03 == 0x01
//	meta mark and 0x03 != 0x01
//	meta mark != 0x10
//	meta mark or 0x03 == 0x01
//	meta mark or 0x03 != 0x01
//	meta mark xor 0x03 == 0x01
//	meta mark xor 0x03 != 0x01
//	meta mark set 0xffffffc8 xor 0x16
//	meta mark set 0x16 and 0x16
//	meta mark set 0xffffffe9 or 0x16
//	meta mark set 0xffffffde and 0x16
//	meta mark set 0x32 or 0xfffff
//	meta mark set 0xfffe xor 0x16
func parseBitwiseMark(tokens []TToken) (int, Tpacketmark) {
	retMark := Tpacketmark{}
	skipCount := 0
	if len(tokens) >= 4 {
		isNum, n, isHex := parseNumber(string(tokens[1]))
		if isNum == false || isHex == false {
			log.Panicf("Token '%s' is not a number (hex or decimal) for usage with bitwise operations", tokens[1])
		}
		retMark.OperatorPacket = tokens[0] // operator against packet
		retMark.OperandPacket = n          // operand against packet
		retMark.OperatorResult = tokens[2] // operator against result
		isNum, n, isHex = parseNumber(string(tokens[3]))
		if isNum == false || isHex == false {
			log.Panicf("Token '%s' is not a number (hex or decimal) for usage with bitwise operations", tokens[3])
		}
		retMark.OperandResult = n // operand against the result
		skipCount = 4
	} else if len(tokens) == 1 {
		// i.e. 'mark != 0x10'
		// i.e. 'mark 0x00000032'
		isNum, n, isHex := parseNumber(string(tokens[0]))
		if isNum == false || isHex == false {
			log.Panicf("Token '%s' is not a number (hex or decimal) for usage with bitwise operations", tokens[3])
		}
		retMark.OperandResult = n // operand against the result
		skipCount = 1
	}
	return skipCount, retMark
}

// Returns 0 or more of either single or paired series of numbers
// For example, if token='32,64,128-256,2048' then the return
// value will be ((32,-), (64,-), (128,256), (2048,-))
func tokenToInt(token TToken) (bool, [][2]int) {
	ret := [][2]int{}
	isNumber := false
	// if it contains '-', it's ranged, if it contains ',' then it's series
	sl := strings.Split(string(token), ",")
	for _, s := range sl {
		var minmax [2]int
		mm := strings.Split(s, "-")
		isNum, n, isHex := parseNumber(mm[0])
		if isNum || isHex {
			isNumber = true
			minmax[0] = n
		} else {
			// no need to proceed further if it's NaN
			return false, ret
		}

		if len(mm) > 1 {
			isNum, n, isHex = parseNumber(mm[1])
			if isNum || isHex {
				isNumber = true
				minmax[1] = n
			}
		}
		ret = append(ret, minmax)
	}
	return isNumber, ret
}

// Return: bool[parm0] isNumber,int[parm1] converted (decimal) value bool[parm2] isHex
// NOTE: If you are passing a hex value without indication, it's hard to guess
// for example, an HEX value '1000', without the "0x" Prefix, this method will
// have to assume it is 1000 decimal (base 10); even if you prepend with "0"
// so that it is "01000", conversions will think it is decimal 1000!  But
// Because there are cases of '01' (as in paradigm of '0A', '0D', '20'),
// if it is prefixed with "0", we'll assume Hex (but will still treat '20' as decimal!)
// So if you know that you're passing a Hex value (i.e. '20'), just pass it as "0"+"20"
// i.e. isNumber, iBase10, isHex := isNumber("0" + myHexString)
func parseNumber(s string) (bool, int, bool) {
	iBase10, err := strconv.Atoi(s) // note: this will treat "020" as integer 20
	isNumber := err == nil
	isHex := false
	if s != "" && !isNumber {
		// if err16 == nil, then it must have been format such as "100D"
		i16, err16 := strconv.ParseInt(s, 16, 64)
		i16g, err16g := strconv.ParseInt(s, 0, 64) // in case s already is prefixed with '0x'
		// strconv.ParsInt() recognizes hex-formatted numbers, but to do so, the string _MUST_ start with '0x' (or '0X') and set base==0
		// if err16x == nil, then it must have been format such as "0x100D"
		i16x, err16x := strconv.ParseInt("0x"+s, 0, 64)
		// NOTE: Because a HEX value can start as '0D', we do not assume Octal (00D) and assume Hex (0x0D)
		isHex = (err16 == nil) || (err16x == nil) || (err16g == nil) || (s[:1] == "0")
		if isHex {
			if err16 == nil {
				iBase10 = int(i16) // i.e. 0x2000 is stored as 8192
				isNumber = true
			} else if err16x == nil {
				iBase10 = int(i16x) // i.e. 0x0800 is stored as 2048
				isNumber = true
			} else if err16g == nil {
				iBase10 = int(i16g) // i.e. 0x0800 is stored as 2048
				isNumber = true
			}
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

func parseCommaSeparated(s TToken) []TToken {
	var retList []TToken
	// input: "a,b,c,d-h,i" (no space)
	split := strings.Split(string(s), ",")
	for _, sc := range split {
		retList = append(retList, TToken(sc))
	}
	if logLevel > 2 {
		log.Printf("\tCSV: %s -> {%+v}(%d)", s, retList, len(retList))
	}
	return retList
}

func parseTable(slist []TToken) *TTable {
	// Example: 'table ip filter', 'table ip6 nat'
	if len(slist) < 2 || len(slist) > 3 {
		log.Panicf("table must have at least 1 parameter (if family missing, defaults to 'ip' family), i.e. 'table ip filter', 'table ip6 nat' (len:%d, '%+v')", len(slist), slist)
	}
	var n TTableName
	var f TAddressFamily
	if len(slist) == 2 {
		f = CAddressFamilyIP
		n = TTableName(slist[1])
	} else {
		f = TAddressFamily(slist[1])
		n = TTableName(slist[2])
	}
	table := TTable{Name: n}
	switch TAddressFamily(f) {
	case CAddressFamilyIP:
		table.Family = CAddressFamilyIP
	case CAddressFamilyIP6:
		table.Family = CAddressFamilyIP6
	case CAddressFamilyINET:
		table.Family = CAddressFamilyINET
	case CAddressFamilyARP:
		table.Family = CAddressFamilyARP
	case CAddressFamilyBridge:
		table.Family = CAddressFamilyBridge
	case CAddressFamilyNetDev:
		table.Family = CAddressFamilyNetDev
	default:
		log.Panicf("Unhandled Address Family: '%s' (in '%+v')", slist[1], slist)
	}
	return &table
}

// i.e. 'chain input', 'chain OUTPUT'
func parseChain(slist []TToken) (TChainName, *TChain) {
	// Example: 'chain input {...}'
	if len(slist) != 2 {
		log.Panicf("Chain must have a chainname associated to it; i.e. 'chain INPUT' (in '%+v')", slist)
	}
	chainName := TChainName(slist[1])
	chain := new(TChain)
	return chainName, chain
}

// FindTable attempts to locate table (tn) via inspections to both
// map key as well as the actual Table name
func (thisNft Nftables) FindTable(f TAddressFamily, tn TTableName) *TTable {
	var ret *TTable = nil
	un := MakeUniqueName(f, tn)

	// first, do the quick thing, see if TTable.Name matches map key
	if v, ok := thisNft.Tables[un]; ok {
		if v.Name == tn && v.Family == f {
			ret = &v
		}
	} else {
		// Do not trust the map-Key, walk through the collection for real table name
		for _, v := range thisNft.Tables {
			// key: table name (ignored, since we did not find it from above), value: TTable
			if v.Name == tn && v.Family == f {
				ret = &v
			}
		}
	}
	return ret
}

func MakeUniqueName(f TAddressFamily, tn TTableName) TUniqueTableName {
	return TUniqueTableName(string(f) + "." + string(tn))
}

// AddTable inspects first determines if the table already have a TTable in place,
// and if it does, returns false to indicate to the caller that table was not added
// Normally, if TAddressFamily is not present (i.e. 'nft add table [AddressFamily] TableName')
// then it defaults to 'ip' family, but caller will have to explicitly pass CAddressFamilyIP
func (thisPNft *Nftables) AddTable(f TAddressFamily, tn TTableName) *TTable {
	pT := thisPNft.FindTable(f, tn)
	if pT == nil {
		// create one
		pT = new(TTable)
		pT.Name = tn
		pT.Family = f
		un := MakeUniqueName(f, tn)
		if (*thisPNft).Tables == nil {
			(*thisPNft).Tables = make(map[TUniqueTableName]TTable)
		}
		(*thisPNft).Tables[un] = *pT
	}
	return pT
}

func (thisROTable TTable) FindChain(cn TChainName) *TChain {
	pChain := thisROTable.Chains[cn] // chains are maps based on key=TChainName
	if pChain == nil {
		s := TChainName(strings.ToLower(string(cn)))
		pChain = thisROTable.Chains[s]
		if pChain == nil {
			s = TChainName(strings.ToUpper(string(cn)))
			pChain = thisROTable.Chains[s]
		}
	}
	return pChain
}

// The syntax to add base chains is the following:
//	% nft add chain [<family>] <table-name> <chain-name> { type <type> hook <hook> priority <value> \; }
func (thisPTable *TTable) RegisterChainWithRule(cn TChainName, ct TChainType, h THookName, p Tpriority) *TChain {
	foundChain := thisPTable.FindChain(cn)
	if foundChain == nil {
		// Chain doesn't exist
		foundChain = new(TChain)
		thisPTable.Chains[cn] = foundChain
	}
	return foundChain
}

// Minimum you need is Family to determine which table to register to, and Name but
// because this is based on TTable (i.e. Family="ip", Table="filter")), we already know which Family
// it belongs to.  Property will need to be added manually
func (thisPTable *TTable) RegisterChain(cn TChainName) *TChain {
	found := thisPTable.FindChain(cn)
	if found == nil {
		// Chain doesn't exist
		found = new(TChain)
		if len(thisPTable.Chains) == 0 {
			thisPTable.Chains = make(map[TChainName]*TChain, 0)
		}
		thisPTable.Chains[cn] = found
	}
	return found
}

func (thisPChainHeadRO *TChain) GetTail() *TChain {
	tail := thisPChainHeadRO
	current := thisPChainHeadRO
	for {
		if current == nil {
			return tail
		}
		tail = current
		current = tail.Next
	}
}

func (thisPChainHead *TChain) AppendChain(pTailChain *TChain) {
	tail := thisPChainHead.GetTail()
	tail.Next = pTailChain
}

func (thisPChainHead *TChain) FindChainRule(s1 string) *TChain {
	current := thisPChainHead
	sl1 := strings.ToLower(s1)
	for current != nil {
		for _, s := range current.Rule.SRule {
			if strings.ToLower(s) == sl1 {
				return current
			}
		}
	}
	return nil
}

// ChainRule expects tokenized list of string so that it does not have to do the parsing of
// quoted strings (i.e. [comment] ["this is a comment, so it's 2 tokens"])
func (thisPChainHead *TChain) ChainRule(cmd TRuleCommand, ruleRO *TTextStatement) bool {
	processed := false
	r := thisPChainHead.ParseChainRule(ruleRO)
	pCurrentChain := thisPChainHead.GetTail()
	switch cmd {
	case CRuleCommandAdd:
		{
			processed = r != nil
			if processed {
				pCurrentChain.Next = new(TChain)
				pCurrentChain = pCurrentChain.Next
				pCurrentChain.Rule = *r
			}
		}
	case CRuleCommandInsert:
		{
			processed = r != nil
			log.Panicf("Chain command '%s' currently not supported!\n", cmd)
		}
	case CRuleCommandDelete:
		{
			log.Panicf("Chain command '%s' currently not supported!\n", cmd)
		}
	}

	return processed
}

// Statement is the action performed when the packet match the rule. It could be terminal and non-terminal.
// In a certain rule we can consider several non-terminal statements but only a single terminal statement.
func (thisPChainHead *TChain) ParseChainRule(ruleRO *TTextStatement) *TRule {
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(ruleRO, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", ruleRO)
	}
	//token := TToken(strings.ToLower(strings.TrimSpace(currentRule.Tokens[0])))
	if logLevel > 1 {
		log.Printf("\t\t\t\tChain Rule:Depth=%d:%+v(Statements:%d)", currentRule.Depth, currentRule.Tokens, len(currentRule.SubStatement))
	}

	newTail := new(TChain) // append it to the tail of the existing chain
	newTail.Rule.SRule = currentRule.Tokens

	switch tokens[0] {
	case CTokenChainType:
		ret := parseChainType(currentRule)
		if ret != nil {
			newTail.Rule.Type = *ret
		}
	case CTokenChainHook:
		log.Panicf("Token '%s' encountered without keyword 'type' (in %+v)", tokens, currentRule)
	case CTokenChainPriority:
		log.Panicf("Token '%s' encountered without keyword 'type' (in %+v)", tokens, currentRule)
	case CTokenChainPolicy:
		newTail.Rule.Policy = parseDefaultPolicy(currentRule)
		// try to locate existing ChainType and set that Policy if not set yet...

	case CTokenMatchIP:
		ret := parsePayloadIp(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Ip = *ret
		}
	case CTokenMatchIP6:
		ret := parsePayloadIp6(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Ip6 = *ret
		}
	case CTokenMatchTCP:
		ret := parsePayloadTcp(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Tcp = *ret
		}
	case CTokenMatchUDP:
		ret := parsePayloadUdp(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Udp = *ret
		}
	case CTokenMatchUDPLite:
		ret := parsePayloadUdpLite(currentRule)
		if ret != nil {
			newTail.Rule.Payload.UdpLite = *ret
		}
	case CTokenMatchSCTP:
		ret := parsePayloadSctp(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Sctp = *ret
		}
	case CTokenMatchDCCP:
		ret := parsePayloadDccp(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Dccp = *ret
		}
	case CTokenMatchAH:
		ret := parsePayloadAh(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Ah = *ret
		}
	case CTokenMatchESP:
		ret := parsePayloadEsp(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Esp = *ret
		}
	case CTokenMatchComp:
		ret := parsePayloadIpComp(currentRule)
		if ret != nil {
			newTail.Rule.Payload.IpComp = *ret
		}
	case CTokenMatchICMP:
		ret := parsePayloadIcmp(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Icmp = *ret
		}
	case CTokenMatchICMPv6:
		ret := parsePayloadIcmpv6(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Icmpv6 = *ret
		}
	case CTokenMatchEther:
		ret := parsePayloadEther(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Ether = *ret
		}
	case CTokenMatchDST:
		ret := parsePayloadDst(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Dst = *ret
		}
	case CTokenMatchFrag:
		ret := parsePayloadFrag(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Frag = *ret
		}
	case CTokenMatchHBH:
		ret := parsePayloadHbh(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Hbh = *ret
		}
	case CTokenMatchMH:
		ret := parsePayloadMh(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Mh = *ret
		}
	case CTokenMatchRT:
		ret := parsePayloadRt(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Rt = *ret
		}
	case CTokenMatchVLAN:
		ret := parsePayloadVlan(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Vlan = *ret
		}
	case CTokenMatchARP:
		ret := parsePayloadArp(currentRule)
		if ret != nil {
			newTail.Rule.Payload.Arp = *ret
		}
	case CTokenMatchCT:
		ret := parseConnTrack(currentRule)
		if ret != nil {
			newTail.Rule.ConnTrack = *ret
		}
	case CTokenMatchMeta:
		ret := parseMeta(currentRule)
		if ret != nil {
			newTail.Rule.Meta = *ret
		}
	default:
		{
			// first, check if it is of 'meta' tokens, which can be without it (i.e. 'iif lo accept')
			if IsMetaRule(currentRule) == false {
				// meta parsed as nil, so assume it's unknown
				log.Panicf("Unhandled chain Rule '%v' (in '%+v') - TokenIndex=%d", tokens, currentRule, iTokenIndex)
			} else {
				// parse for meta
				ret := parseMeta(currentRule)
				if ret != nil {
					newTail.Rule.Meta = *ret
				}
			}
		}
	}
	if newTail != nil {
		thisPChainHead.AppendChain(newTail)
	}
	//log.Printf("# New rule: %+v\n\n", newTail.Rule.SRule)
	return &newTail.Rule
}

// type <type> hook <hook> [device <device>] priority <priority> \; [policy <policy> \;]
func parseChainType(rule *TTextStatement) *TRuleType {
	retType := new(TRuleType)
	for i := 0; i < len(rule.Tokens); i++ {
		switch TToken(rule.Tokens[i]) {
		case CTokenChainType:
			i++
			switch TChainType(strings.ToLower(rule.Tokens[i])) {
			case CChainTypeFilter:
				retType.ChainType = CChainTypeFilter
			case CChainTypeRoute:
				retType.ChainType = CChainTypeRoute
			case CChainTypeNat:
				retType.ChainType = CChainTypeNat
			default:
				log.Panicf("Unkonwn chain Type '%s' (%+v)", rule.Tokens[i], rule)
			}

		case CTokenChainHook:
			i++
			retType.Hook = THookName(rule.Tokens[i])

		case CTokenChainDevice:
			i++
			retType.Device = rule.Tokens[i]

		case CTokenChainPriority:
			i++
			p, err := strconv.Atoi(rule.Tokens[i])
			if err == nil {
				retType.Priority = Tpriority(p)
			} else {
				log.Panicf("Unable to convert '%s' to int value for Priority - %-v", rule.Tokens[i], err)
			}

		case CTokenChainPolicy:
			retType.Policy = parseDefaultPolicy(rule)
			i++
		}
	}
	return retType
}
