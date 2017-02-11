package nftables

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Deserializes rules files into Nftables instance
func Read(path string) (*Nftables, error) {
	ret := new(Nftables)
	var err error = nil

	// hopefully, an nftable rule files do not exceed RAM _AND_ doesn't have INCLUDE statement
	// we'll revisit the INCLUDE injection later...
	inFile, openErr := os.Open(path)
	if openErr != nil {
		log.Panic(openErr)
	}
	defer inFile.Close()
	err = openErr

	buffer := make([]byte, 1024*1024*16)
	nb, rErr := inFile.Read(buffer)
	if rErr != nil || nb > len(buffer) {
		log.Panicf("Increase the buffer size to more than %d bytes", nb)
	}
	err = rErr
	tables := MakeStatements(string(buffer)) // bad bad bad!

	var debugStream *os.File = nil
	dbgOutFileName := "/tmp/nft.rules.out"
	if CLogLevel >= CLogLevelInfo {
		debugStream, err = os.Create(dbgOutFileName)
		if err == nil {
			defer debugStream.Close()
		}
	}
	// deserialize []*TTextStatement
	//for _, ts := range tables {
	//	ts.deserializeRecursive(ret, nil, CAddressFamilyUndefined, nil)
	//}
	for it, ts := range tables {
		if CLogLevel > CLogLevelVerbose {
			log.Printf("#%d:Parsing: %+v", it, ts)
		}

		var retTable *TTable = nil // because map[] won't tell us what just got added, it's best to just track returned TTable
		retTable, err = ts.deserialize(ret)

		if debugStream != nil {
			if CLogLevel > CLogLevelInfo {
				// dump just the current table
				retTable.Dump(debugStream, fileTabs)

			} else if CLogLevel == CLogLevelInfo {
				// each time, re-dump the entire current nftables
				ret.Dump(debugStream, fileTabs)
			}
		}
	}
	if CLogLevel > CLogLevelInfo && debugStream != nil {
		debugStream.Close()
		if b, berr := os.Open(dbgOutFileName); berr == nil {
			defer b.Close()
			// just "cat" it to stdout
			if _, cErr := io.Copy(os.Stdout, b); cErr != nil {
				log.Print(cErr)
			}
		}
	}
	return ret, err
}

// Serializes Nftables into rules file
func (thisRO Nftables) Write(path string) error {
	var cbSerializeTokens THandleTokenCB = func(tokens []TToken, iTokenIndex uint16, iTokenCount uint16, stream *os.File) (uint16, error) {
		s := ""
		var c uint16 = 0
		for _, t := range tokens[iTokenIndex:iTokenCount] {
			s += string(t) + " "
			c++
		}
		nb, wErr := stream.WriteString(s)
		log.Printf("Write %d bytes of string '%s'", nb, s)
		return iTokenIndex + c, wErr
	}

	var err error = nil
	if len(thisRO.Tables) > 0 {
		outFile, openErr := os.Create(path)
		if openErr != nil {
			log.Panic(openErr)
		}
		defer outFile.Close()
		err = openErr

		for _, t := range thisRO.Tables {
			for k, _ := range t.Chains {
				err = t.handle(cbSerializeTokens, k, outFile)
			}
		}
	}
	return err
}

// Delegate/lambda function of what to do with the token list
type THandleTokenCB func(tokens []TToken, iTokenIndex uint16, iTokenCount uint16, outFile *os.File) (uint16, error)

func (thisRO TTable) handle(doCB THandleTokenCB, chainName TChainName, outFile *os.File) error {
	c := thisRO.Chains[chainName]
	for c != nil {
		if err := c.handle(doCB, outFile); err != nil {
			return err
		}
		c = c.Next
	}
	//return nil
	panic("CODE ME!")
}

func (thisRO TChain) handle(doCB THandleTokenCB, outFile *os.File) error {
	//r := thisRO.Rule
	panic("Code me!")
	//return nil
}

// Dump is passed with stream (i.e. memory stream, io stream, etc) and build
// stream as it goes, and the end result should then be up to the caller to print it...
func (pThisNftable *Nftables) Dump(outFile *os.File, tabs string) {
	_, err := outFile.WriteString("\n# ---------------------------------------------------- nftables\n")
	if err != nil {
		log.Print(err)
	}
	for k, v := range pThisNftable.Tables {
		_, err = outFile.WriteString(fmt.Sprintf("# %s\n", k))
		if err != nil {
			log.Print(err)
		}
		v.Dump(outFile, tabs)
	}
	_, err = outFile.WriteString("\n# ----------------------------------------------------\n")
	if err != nil {
		log.Print(err)
	}
}
func (pThisTable *TTable) Dump(outFile *os.File, tabs string) {
	_, err := outFile.WriteString(fmt.Sprintf("# === Table Name: %s, Family: %s - Chain Count: %d\n", pThisTable.Name, pThisTable.Family, len(pThisTable.Chains)))
	if err != nil {
		log.Print(err)
	}
	for k, v := range pThisTable.Chains {
		_, err = outFile.WriteString(fmt.Sprintf("#\t--- Chain: %s\n", k))
		if err != nil {
			log.Print(err)
		}
		v.Dump(outFile, tabs)
	}
}
func (pThisChain *TChain) Dump(outFile *os.File, tabs string) {
	currentChain := pThisChain
	for currentChain != nil {
		if currentChain.HasExpression() {
			st := ""
			for _, t := range currentChain.GetTokens() {
				st += t.ToString() + " "
			}
			_, err := outFile.WriteString(fmt.Sprintf("#\t\t%s%s\n", tabs[:currentChain.Type.Depth], st))
			if err != nil {
				log.Print(err)
			}
		} else {
			_, err := outFile.WriteString("# WARNING: Empty chain\n")
			if err != nil {
				log.Print(err)
			}
			log.Printf("WARNING: Chain %+v has no tokens to dump", pThisChain)
		}
		currentChain = currentChain.Next
	}
}

// As a parent, it should deserialize itself and its children; should be agnostic of its siblings
func (pThisStatement *TTextStatement) deserializeRecursive(pNFT *Nftables, pCurrentTable *TTable, caf TAddressFamily, pCurrentChain *TChain) error {
	var err error = nil
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

		token := pThisStatement.ToToken(0)
		switch token {
		case CTokenTable:
			sr := pThisStatement.stripRule()
			t := parseTable(sr)
			pCurrentTable = pNFT.AddTable(t.Family, t.Name)
			caf = t.Family

		case CTokenChain:
			if pCurrentTable == nil {
				log.Panicf("Unable to deal with nil Table for tokens:\n\t%+v (len: %d)\n\n", pThisStatement.Tokens, len(pThisStatement.Tokens))
			}
			sr := pThisStatement.stripRule()
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

			cErr := pCurrentChain.ParseChainRule(pThisStatement, 0)
			if cErr != nil {
				err = cErr
				log.Panicf("Unable to add chain rule '%+v' - %+v", pThisStatement.Tokens, err)
			}
		}
	}

	// next, parse all statements for the token
	for _, tss := range pThisStatement.SubStatement {
		err = tss.deserializeRecursive(pNFT, pCurrentTable, caf, pCurrentChain)
		if err != nil {
			break
		}
	}
	return err
}

// this method does not recurse
func (pThisStatement *TTextStatement) deserialize(pNFT *Nftables) (*TTable, error) {
	if pThisStatement == nil {
		log.Panicf("pThisStatement passed is nill!")
	}

	tokens, iTokenIndex, currentRule, err := pThisStatement.getNextToken(0, 1, true)
	if (len(pThisStatement.Tokens) == 0) && (len(pThisStatement.SubStatement) == 0) {
		return nil, fmt.Errorf("There are no tokens found on %+v", pThisStatement)
	}
	if currentRule == nil {
		return nil, fmt.Errorf("There are no substatements to process for %+v", pThisStatement)
	}

	var pCurrentTable *TTable
	if len(tokens) == 0 {
		if tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true); err != nil {
			return nil, fmt.Errorf("Unable to proceed to next token for  %+v -> %+v", pThisStatement, pCurrentTable)
		}
	}
	tToken := tokens[0]
	for pCurrentTable == nil {
		switch tToken {
		case CTokenTable:
			sr := pThisStatement.stripRule()
			t := parseTable(sr)
			pCurrentTable = pNFT.AddTable(t.Family, t.Name)
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)

		case CTokenSC, CTokenOB, CTokenCB, CTokenHash, "":
			// Evaluate next token
			if tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true); err != nil {
				return nil, fmt.Errorf("Expected %s token: Unable to proceed to next token for  %+v -> %+v", CTokenTable, pThisStatement, pCurrentTable)
			}
			tToken = tokens[0]

		default:
			return nil, fmt.Errorf("Encountered non-Table token '%s' in table loop (%+v)", tToken, pThisStatement)
		}
	}

	// before we walk the chains, make sure we have a table now
	if pCurrentTable == nil {
		return nil, fmt.Errorf("Unable to deal with nil Table")
	}
	if CLogLevel > CLogLevelNone {
		log.Printf("Table '%s' of Family '%+v' has %d chains (%+v)", pCurrentTable.Name, pCurrentTable.Family, len(pThisStatement.SubStatement), pCurrentTable)
	}
	// walk each series of chains
	for _, currentExprStatement := range currentRule.SubStatement {
		//currentRule = currentExprStatement
		var pCurrentChain *TChain
		chainName := TChainName("")
		if len(currentExprStatement.Tokens) == 0 {
			continue
		}

		cToken := currentExprStatement.ToToken(0)
		switch cToken {
		case CTokenTable:
			return nil, fmt.Errorf("Cannot have 'table' withinside 'chain' (%+v)", currentExprStatement)

		case CTokenChain:
			if pCurrentTable == nil {
				return nil, fmt.Errorf("Unable to deal with nil Table for tokens:\n\t%+v (len: %d)\n\n", currentExprStatement.Tokens, len(currentExprStatement.Tokens))
			}
			sr := currentExprStatement.stripRule()
			chainName, _ = parseChain(sr)
			pCurrentChain = pCurrentTable.RegisterChain(chainName)
			//tokens,iTokenIndex,currentRule,err = currentRule.getNextToken( iTokenIndex, 1)

		case CTokenSC, CTokenOB, CTokenCB, CTokenHash, "":
			// do nothing
			continue

		default:
			return nil, fmt.Errorf("Encountered non-Chain rules token '%s' in chain loop (%+v)", cToken, currentExprStatement)
		}

		// before we parse the chain rules, make sure we have the chain to associate it with
		if pCurrentChain == nil {
			return nil, fmt.Errorf("Unable to deal with nil Chain")
		}
		if CLogLevel > CLogLevelNone {
			log.Printf("\tChain '%s' (of Table '%s') has %d chain rules (%+v)", chainName, pCurrentTable.Name, len(currentExprStatement.SubStatement), pCurrentChain)
		}
		for iCS, chainS := range currentExprStatement.SubStatement {
			tokens, _, pCurrentChainSubStatement, err := chainS.getNextToken(0, 1, true) // always use TokenIndex=0 and let the parser walk down its subsystems
			if err != nil {
				log.Printf("Unable to find next token - %+v at index=%d - %+v", chainS, iCS, err)
				continue
			}
			// first, parse the tokens - NOTE that what we are interested in are
			// statements that have AT LEAST 2 tokens.  Statements which only
			// have one is usually comments ("#"), beginning of statements ("{"),
			// closing of statements ("}"), or new line (";").  Rest are usually
			// based on two or more (i.e. 'table INPUT')
			if len(chainS.Tokens) == 0 {
				log.Printf("Chain substatement index=%d does not have any tokens. (%+v)", iCS, chainS)
				continue
			}
			if pCurrentChainSubStatement == nil {
				log.Printf("There are no next rules to be processed at Chain Index=%d (%+v)", iCS, chainS)
				pCurrentChainSubStatement = chainS
			}
			if chainS.Depth != (currentExprStatement.Depth + 1) {
				// all sub statements that are of deeper depths *should have* been processed already
				if CLogLevel > CLogLevelDebug {
					log.Printf("\t\t# Skipping %+v: Found Depth(%d), Current Depth(%d), found depth needs to be %d", tokens, chainS.Depth, currentExprStatement.Depth, currentExprStatement.Depth+1)
				}
				continue
			}

			if CLogLevel > CLogLevelNone {
				log.Printf("\t\t%2d:%s%+v(Child Count:%d) - Depth:%d, ChainDepth:%d, NextDepth:%d", iCS, tabs[:chainS.Depth], chainS.Tokens, len(chainS.SubStatement), chainS.Depth, currentExprStatement.Depth, pCurrentChainSubStatement.Depth)
			}
			switch tokens[0] {
			case CTokenTable:
				return nil, fmt.Errorf("Cannot have 'table' withinside 'chain' (%+v) %12p", chainS, pCurrentChainSubStatement)

			case CTokenChain:
				return nil, fmt.Errorf("Cannot have 'chain' withinside 'chain' (%+v) %12p", chainS, pCurrentChainSubStatement)

			case CTokenSC, CTokenOB, CTokenCB, CTokenHash, "":
				// do nothing
				continue

			default:
				// if it is not 'table' or 'chain' tokens, it must be rules to the TChain
				cErr := pCurrentChain.ParseChainRule(pCurrentChainSubStatement, 0)
				if cErr != nil {
					err = fmt.Errorf("Unable to add chain rule '%+v' - %+v", pCurrentChainSubStatement.Tokens, cErr)
				}
			}
		} // chainS
	} // current chain
	return pCurrentTable, err
}

func (pThisRuleRO *TTextStatement) findNextToken(iStartIndex uint16, strip bool) (*TTextStatement, uint16, error) {
	var err error = nil
	pRetNextRule := pThisRuleRO
	retNextIndex := iStartIndex
	caller := ""
	// Caller(1) means the callee of this method (skip 1 stack)
	if _, f, ln, ok := runtime.Caller(1); ok {
		_, fn := filepath.Split(f)
		caller = fmt.Sprintf("%s:%d", fn, ln)
	}
	if pThisRuleRO == nil {
		err = fmt.Errorf("%s:pThisRule must not be nil", caller)
		pRetNextRule = nil
		retNextIndex = 0
	} else {
		tokens := pRetNextRule.ToTokens()
		if strip {
			tokens = pRetNextRule.stripRule()
		}

		if iStartIndex < uint16(len(tokens)) {
			// if here, we've not reached the end of tokens list, so all is good
			retNextIndex = iStartIndex
		} else if (len(tokens) == 0) || (iStartIndex <= uint16(len(tokens))) {
			// if here, currentIndex was the last one, so see if we have children to visit
			// and/or there are no tokens found for this node because the children has holds them
			if len(pThisRuleRO.SubStatement) > 0 {
				for _, ss := range pThisRuleRO.SubStatement {
					//log.Printf("Inspecting %+v", ss)
					if next, iNext, nextErr := ss.findNextToken(0, strip); nextErr == nil {
						pRetNextRule = next
						retNextIndex = iNext
						err = nil
						break // opt out on first valid child we find
					} else {
						err = nextErr
					}
				}
			} else if (pThisRuleRO.Parent != nil) && (pThisRuleRO.Parent.Parent != nil) {
				// if here, there are no child SubStatement thus we have to do the special case and
				// observe the siblings of same parent
				// find THIS statement
				for is, ppS := range pThisRuleRO.Parent.Parent.SubStatement {
					if ppS == pThisRuleRO.Parent {
						// Now, look for siblings
						if len(pThisRuleRO.Parent.Parent.SubStatement) > is+1 {
							n := pThisRuleRO.Parent.Parent.SubStatement[is+1]
							if pThisRuleRO.Depth == n.Depth {
								// we've found deeper depth than current, we can treat it as a child
								pRetNextRule = n
								retNextIndex = 0
								err = nil
							} else {
								err = fmt.Errorf("%s:Unable to locate siblings with lower depths", caller)
								pRetNextRule = nil
								retNextIndex = 0
							}
						}
						break // must opt out no matter what
					}
				}
			} else {
				err = fmt.Errorf("%s:Statement has no substatements", caller)
				pRetNextRule = nil
				retNextIndex = 0
			}
		} else {
			err = fmt.Errorf("%s:Invalid index(%d) - there are only %d tokens in this statement", caller, iStartIndex, len(tokens))
			pRetNextRule = nil
			retNextIndex = 0
		}
	}
	if CLogLevel > CLogLevelVerbose {
		t := TToken("[]")
		if pRetNextRule != nil {
			t = pRetNextRule.ToToken(int(retNextIndex))
		}
		log.Printf("\t>> findNextToken:[%s](%12p) - NextIndex:%d, Next:'%v' (%+v), Error:%v", caller, pRetNextRule, retNextIndex, t, pRetNextRule, err)
	}
	return pRetNextRule, retNextIndex, err
}

// It is expected that caller assumes "next tokens" for current TTextStatement can be empty
// and that the caller will locally upkeep on *TTextStatement returned to be where subsequent
// Tokens will be.  This method will hop to SubStatements or siblings of same parent and
// tries its best to find next TToken preparation.  Because it will do all such work,
// it is recommended that calling method locally hold the returning *TTextSTatement so that
// it doesn't have to do any unnecessary redundant work.
// Ret parm1[[]TToken] : the token that was found (array size based on expectedTokens)
// Ret parm2[uint16] : next token index (relative to next TTextStatement)
// Ret parm3[*TTextStatement] : next statement to reference (see next token index parm2)
// Ret parm4[err] : nil if next token found
func (pThisRuleRO *TTextStatement) getNextToken(iRequestedTokenStartIndexRO uint16, expectedTokens uint16, strip bool) ([]TToken, uint16, *TTextStatement, error) {
	var err error = nil
	pRetNextRule := pThisRuleRO
	retNextIndex := iRequestedTokenStartIndexRO + expectedTokens
	var retTokenList []TToken = []TToken{}
	caller := ""
	// Caller(1) means the callee of this method (skip 1 stack)
	if _, f, ln, ok := runtime.Caller(1); ok {
		_, fn := filepath.Split(f)
		caller = fmt.Sprintf("%s:%d", fn, ln)
	}
	if pThisRuleRO == nil {
		err = fmt.Errorf("%s:Rule expression/statement pointer must not be nil", caller)
		pRetNextRule = nil
		retNextIndex = 0
		panic(err) // need to catch this immediately
		//goto done
	}

	if expectedTokens == 0 {
		err = fmt.Errorf("%s:Expected tokens count should not be zero", caller)
		pRetNextRule = nil
		retNextIndex = 0
		panic(err) // need to catch this immediately
		//goto done
	}

	if iRequestedTokenStartIndexRO > uint16(len(pThisRuleRO.Tokens)) {
		err = fmt.Errorf("%s:The tokens index %d exceeds Token array acount (total token count:%d)", caller, iRequestedTokenStartIndexRO, len(pThisRuleRO.Tokens))
		pRetNextRule = nil
		retNextIndex = 0
		panic(err) // need to catch this immediately
		//goto done
	}

	pRetNextRule, retNextIndex, err = pThisRuleRO.findNextToken(iRequestedTokenStartIndexRO, strip)
	if err == nil {
		// first, do what this method is expected to do, pull out the NEXT tokens requested
		retTokenList = pRetNextRule.ToTokensRange(int(retNextIndex), int(retNextIndex+expectedTokens))
		if CLogLevel > CLogLevelVerbose {
			log.Printf(">> ToTokensRange(%d, %d) -> %v", retNextIndex, retNextIndex+expectedTokens, retTokenList)
		}
		if strip {
			if stripped := pRetNextRule.stripRule(); uint16(len(stripped)) > retNextIndex+expectedTokens {
				retTokenList = stripped[retNextIndex : retNextIndex+expectedTokens]
				if CLogLevel > CLogLevelVerbose {
					log.Printf(">>> StripRule -> %v -> (%d, %d) -> %v", stripped, retNextIndex, retNextIndex+expectedTokens, retTokenList)
				}
			}
		}

		if (len(retTokenList) == 0) || (uint16(len(retTokenList)) != expectedTokens) {
			err = fmt.Errorf("%s:Current statement does not have %d tokens (starting at index=%d)", caller, expectedTokens, retNextIndex)
			pRetNextRule = nil
			retNextIndex = 0
			goto done
		}

		// Now that trivial work is done, next setup for the following pRetNextRule stuff
		if (retNextIndex + expectedTokens) >= uint16(len(pRetNextRule.ToTokens())) {
			// it is NOT an error if we cannot locate NEXT position as long as we have retTokenList,
			// but we need to make sure caller knows there are no NEXT
			pRetNextRule = nil
			retNextIndex = 0
		} else {
			// ideal situation where we have subsequent tokens to follow on current statement, all is done
			retNextIndex = retNextIndex + expectedTokens
			goto done
		}
	}
done:
	// fill in err if not already filled in
	if err == nil {
		if len(retTokenList) == 0 {
			err = fmt.Errorf("%s:There are no tokens", caller)
		} else if uint16(len(retTokenList)) != expectedTokens {
			err = fmt.Errorf("%s:Requested %d tokens, but only were able to extract %d", caller, expectedTokens, len(retTokenList))
		}
	}
	if pRetNextRule == nil {
		// max uint16: 0xFFff
		retNextIndex = 0xFFff // only useful for logging to distinguish valid Index=0 and Invalid one...
	}
	if CLogLevel > CLogLevelVerbose {
		var t []string
		d := -1
		cd := -1
		var pt []string
		if pThisRuleRO != nil {
			t = pThisRuleRO.Tokens
			d = int(pThisRuleRO.Depth)
			if pThisRuleRO.Parent != nil {
				pt = pThisRuleRO.Parent.Tokens
			}
		}
		sNextIndex := strconv.Itoa(int(retNextIndex))
		if pRetNextRule != nil {
			cd = int(pRetNextRule.Depth)
		} else {
			sNextIndex = "(none)"
		}
		log.Printf("\t> getNextToken:[%s] Depth: %d - Index:%d[Req:%d](out of %d), '%v'[@%s], %+v (Depth:%+v), Parent:(%v)",
			caller, d, retNextIndex, iRequestedTokenStartIndexRO, expectedTokens, retTokenList, sNextIndex, t, cd, pt)
		if err != nil {
			log.Printf("\t\t> Error: %s", err.Error())
		}
	}
	return retTokenList, retNextIndex, pRetNextRule, err
}

func (t TToken) parseEquates() (bool, TEquate) {
	isEq := false
	var e TEquate
	switch t {
	case CTokenNE:
		e.NE = new(bool)
		*e.NE = true
		isEq = true
	case CTokenGT, CTokengt:
		e.GT = new(bool)
		*e.GT = true
		isEq = true
	case CTokenGE:
		e.GE = new(bool)
		*e.GE = true
		isEq = true
	case CTokenLT, CTokenlt:
		e.LT = new(bool)
		*e.LT = true
		isEq = true
	case CTokenLE:
		e.LE = new(bool)
		*e.LE = true
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
func parseBitwiseMark(tokens []TToken) (int, *Tpacketmark) {
	retMark := Tpacketmark{}
	skipCount := 0

	if CLogLevel > CLogLevelDebug {
		log.Printf("\t#Parsing '%+v' for Bitwise 'mark'", tokens)
	}

	if len(tokens) >= 4 {
		isNum, n, isHex := tokens[1].parseNumber()
		if isNum == false || isHex == false {
			log.Panicf("Token '%s' is not a number (hex or decimal) for usage with bitwise operations", tokens[1])
		}
		retMark.OperatorPacket = tokens[0] // operator against packet
		retMark.OperandPacket = n          // operand against packet
		retMark.OperatorResult = tokens[2] // operator against result
		isNum, n, isHex = tokens[3].parseNumber()
		if isNum == false || isHex == false {
			log.Panicf("Token '%s' is not a number (hex or decimal) for usage with bitwise operations", tokens[3])
		}
		retMark.OperandResult = n // operand against the result
		skipCount = 4
	} else if len(tokens) == 1 {
		// i.e. 'mark != 0x10'
		// i.e. 'mark 0x00000032'
		isNum, n, isHex := tokens[0].parseNumber()
		if isNum == false || isHex == false {
			log.Panicf("Token '%s' is not a number (hex or decimal) for usage with bitwise operations", tokens[3])
		}
		retMark.OperandResult = n // operand against the result
		skipCount = 1
	}
	if CLogLevel > CLogLevelDebug {
		log.Printf("\t\t#Bitwise 'mark' result: '%+v' (skip count: %d tokens)", retMark, skipCount)
	}

	return skipCount, &retMark
}

// Returns 0 or more of either single or paired series of numbers
// For example, if token='32,64,128-256,2048' then the return
// value will be ((32,-), (64,-), (128,256), (2048,-))
func (token TToken) tokenToInt() (bool, [][2]int) {
	ret := [][2]int{}
	isNumber := false
	if CLogLevel > CLogLevelDebug {
		log.Printf("\t# Parsing '%+v' to be converted to integers", token)
	}

	// if it contains '-', it's ranged, if it contains ',' then it's series
	tl := token.parseCommaSeparated()
	for _, t := range tl {
		minmax := [2]int{}
		isNum, n, isHex := t[0].parseNumber()
		if isNum || isHex {
			isNumber = true
			minmax[0] = n
		} else {
			// no need to proceed further if even ONE of the list are NaN (i.e. '{0, sudo, 5-10}')
			return false, ret
		}
		if t[1] != "" {
			isNum, n, isHex = t[1].parseNumber()
			if isNum || isHex {
				isNumber = true
				minmax[1] = n
			} else {
				// no need to proceed further if even ONE of the list are NaN (i.e. '{0, sudo, 5-10}')
				return false, ret
			}
		}
		ret = append(ret, minmax)
	}
	if CLogLevel > CLogLevelDebug {
		log.Printf("\t## TokenToInt result: '%+v', %d tokens", ret, len(ret))
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
func (t TToken) parseNumber() (bool, int, bool) {
	iBase10, err := strconv.Atoi(t.ToString()) // note: this will treat "020" as integer 20
	isNumber := err == nil
	isHex := false
	if t.ToString() != "" && !isNumber {
		// if err16 == nil, then it must have been format such as "100D"
		i16, err16 := strconv.ParseInt(t.ToString(), 16, 64)
		i16g, err16g := strconv.ParseInt(t.ToString(), 0, 64) // in case s already is prefixed with '0x'
		// strconv.ParsInt() recognizes hex-formatted numbers, but to do so, the string _MUST_ start with '0x' (or '0X') and set base==0
		// if err16x == nil, then it must have been format such as "0x100D"
		i16x, err16x := strconv.ParseInt("0x"+t.ToString(), 0, 64)
		// NOTE: Because a HEX value can start as '0D', we do not assume Octal (00D) and assume Hex (0x0D)
		isHex = (err16 == nil) || (err16x == nil) || (err16g == nil) || (t.ToString()[:1] == "0")
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

func lookupServicePort(port string) (int, error) {
	//log.Printf("\tLooking up service port '%s'\n", port)
	p, err := strconv.Atoi(port) // Q: Should use parseNumber() here too?
	if err != nil {
		// use net.LookupPort() to see if we get anything
		p, err = net.LookupPort("tcp", port)
		if err != nil {
			p, err = net.LookupPort("udp", port)
			if err != nil {
				err = fmt.Errorf("Unable to convert Port:%s into integer - %v", port, err)
			}
		}
	}
	if p == 0 {
		err = fmt.Errorf("Token '%s' cannot be converted to any known port", port)
	}
	if CLogLevel > CLogLevelDebug && err == nil {
		log.Printf("\t\tService port '%s' -> %d\n", port, p)
	}
	return p, err
}

// returns single, paired-range ('-'), or multiple (',' and can be list of paired-ranges) based IPs
func (t TToken) tokenToIP() ([][2]TIPAddress, error) {
	var retIP [][2]TIPAddress
	var err error
	pairedList := t.parseCommaSeparated()
	for _, pair := range pairedList {
		newIPs := [2]TIPAddress{}
		ip, ipnet, ipErr := net.ParseCIDR(string(pair[0]))
		err = ipErr
		if err == nil {
			newIPs[0] = TIPAddress{IP: ip, IPNet: *ipnet, SAddr: t, IsIPv6: len(ip) == net.IPv6len}
		}
		if len(pair[1]) > 0 {
			ip, ipnet, ipErr := net.ParseCIDR(string(pair[1]))
			err = ipErr
			if err == nil {
				newIPs[1] = TIPAddress{IP: ip, IPNet: *ipnet, SAddr: t, IsIPv6: len(ip) == net.IPv6len}
			}
		}
		retIP = append(retIP, newIPs)
	}
	return retIP, err
}

// Splits comma-separated tokens into paired list
func (s TToken) parseCommaSeparated() [][2]TToken {
	var retList [][2]TToken
	if strings.HasPrefix(string(s), "\"") || strings.HasPrefix(string(s), "'") {
		// don't want to mess with quoted string based tokens
		retList = append(retList, [2]TToken{s, TToken("")})
		return retList
	}

	// input: "a,b,c,d-h,i" (no space)
	// output: {'a', ''}, {'b', ''}, {'c', ''}, {'d', 'h'}, {'i', ''} (5 paired tokens)
	split := strings.Split(string(s), ",")
	for _, sc := range split {
		pair := [2]TToken{"", ""}
		sd := strings.Split(string(sc), "-")
		for i, s := range sd {
			// cannot/will not handle cases of 'a-b-c', will only take the first pair
			if i < 2 {
				pair[i] = TToken(s)
			}
		}
		retList = append(retList, pair)
	}
	if CLogLevel > CLogLevelDebug {
		log.Printf("\tCSV: %s -> {%+v}(%d)", s, retList, len(retList))
	}
	return retList
}

// input: '22:accept,23:drop' (assume they are single token)
func (t TToken) parseVMap() ([]TVMap, error) {
	retMap := []TVMap{}
	var err error = nil
	if strings.Contains(string(t), ":") == false {
		err = fmt.Errorf("Token '%v' does not seem to be a vmap token (does not contain ':' seprator)", t)
		return retMap, err
	}
	// vlist format: {'22:accept', ''}, {'23:drop', ''}
	vlist := t.parseCommaSeparated()
	for _, v := range vlist {
		sl := strings.Split(string(v[0]), ":")
		if len(sl) == 2 {
			vm := TVMap{Verdict: TVerdict{token: TToken(sl[1])}} // 2nd token is always the verdict
			if isNum, nl := TToken(sl[0]).tokenToInt(); isNum {
				*vm.Port = TPort(nl[0][0])
			} else {
				*vm.ServicePort = TToken(sl[0])
				// save time on lookup later
				if pn, lerr := lookupServicePort(sl[0]); lerr == nil {
					*vm.Port = TPort(pn)
				}
			}
			retMap = append(retMap, vm)
		} else {
			err = fmt.Errorf("Token '%v' is not in the format of '<port>:<verdict>'", t)
			return retMap, err
		}
	}

	return retMap, err
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
			ret = v
		}
	} else {
		// Do not trust the map-Key, walk through the collection for real table name
		for _, v := range thisNft.Tables {
			// key: table name (ignored, since we did not find it from above), value: TTable
			if v.Name == tn && v.Family == f {
				ret = v
			}
		}
	}
	return ret
}

func MakeUniqueName(f TAddressFamily, tn TTableName) TUniqueTableName {
	return TUniqueTableName(string(f) + "." + string(tn))
}

func (thisPNft *Nftables) Append(newTable *TTable) {
	if (*thisPNft).Tables == nil {
		(*thisPNft).Tables = make(map[TUniqueTableName]*TTable)
	}
	un := MakeUniqueName(newTable.Family, newTable.Name)
	(*thisPNft).Tables[un] = newTable
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
		thisPNft.Append(pT)
	}
	if CLogLevel > CLogLevelInfo {
		t := ""
		for k, v := range thisPNft.Tables {
			t += fmt.Sprintf("'%s.%s'(%s:%d) ", v.Family, v.Name, k, len(v.Chains))
		}
		log.Printf("# AddTable: %s", t)
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

//// The syntax to add base chains is the following:
////	% nft add chain [<family>] <table-name> <chain-name> { type <type> hook <hook> priority <value> \; }
//func (thisPTable *TTable) RegisterChainWithRule(cn TChainName, ct TChainType, h THookName, p Tpriority) *TChain {
//	foundChain := thisPTable.FindChain(cn)
//	if foundChain == nil {
//		// Chain doesn't exist
//		foundChain = new(TChain)
//		thisPTable.Chains[cn] = foundChain
//	}
//	if CLogLevel > CLogLevelInfo {
//		c := ""
//		for k, _ := range thisPTable.Chains {
//			c += fmt.Sprintf("'%s' ", k)
//		}
//		log.Printf("\t# [%s.%s] RegisterChains: %+v", thisPTable.Family, thisPTable.Name, c)
//	}
//	return foundChain
//}

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
	if CLogLevel > CLogLevelInfo {
		c := ""
		for k, _ := range thisPTable.Chains {
			c += fmt.Sprintf("'%s' ", k)
		}
		log.Printf("\t# [%s.%s] RegisterChains: %+v", thisPTable.Family, thisPTable.Name, c)
	}
	return found
}

func (thisPChainHeadRO *TChain) GetTail() (*TChain, error) {
	var err error = nil
	if thisPChainHeadRO == nil {
		err = fmt.Errorf("Chain cannot be nil")
	}

	// walk the linked list to the tail
	tail := thisPChainHeadRO
	current := thisPChainHeadRO
	for {
		if current == nil {
			return tail, err
		}
		tail = current
		current = tail.Next
	}
}

func (thisPChainHead *TChain) AppendChain(pTailChain *TChain) error {
	caller := ""
	// Caller(1) means the callee of this method (skip 1 stack)
	if _, f, ln, ok := runtime.Caller(1); ok {
		_, fn := filepath.Split(f)
		caller = fmt.Sprintf("%s:%d", fn, ln)
	}

	tail, err := thisPChainHead.GetTail()
	if err == nil {
		if CLogLevel > CLogLevelDebug {
			log.Printf("\t\t#[%s] Appending Chain %12p to %12p", caller, pTailChain, thisPChainHead)
		}
		tail.Next = pTailChain
	}
	return err
}

//func (thisPChainHead *TChain) FindChainRule(s1 string) (*TChain, error) {
//	var err error
//	if thisPChainHead == nil {
//		err = fmt.Errorf("Chain (head) cannot be nil!")
//	}
//
//	current := thisPChainHead
//	sl1 := strings.ToLower(s1)
//	for current != nil {
//		for _, s := range current.Rule.SRule.Tokens {
//			if strings.ToLower(string(s)) == sl1 {
//				return current, err
//			}
//		}
//	}
//	err = fmt.Errorf("Unable to locate Chain '%s'", s1)
//	return nil, err
//}

//// Append new Rule to current pChain and return pointer to Next
//func (pChain *TChain) SetChain(rule TRule) (*TChain, error) {
//	// append new
//	err := pChain.AppendChain(new(TChain))
//	if err == nil {
//		pChain.Next.Rule = rule
//		if CLogLevel > CLogLevelDebug {
//			log.Printf("\t\t\t#Setting NEXT Chain with %12p (%+v) for %12p", pChain.Next, rule.SRule, pChain)
//		}
//	}
//	return pChain.Next, err
//}

// Statement is the action performed when the packet match the rule. It could be terminal and non-terminal.
// In a certain rule we can consider several non-terminal statements but only a single terminal statement.
func (thisPChainHead *TChain) ParseChainRule(ruleRO *TTextStatement, iTokenIndexRO uint16) error {
	if ruleRO == nil {
		log.Panicf("Unable to handle chain rule that is nil")
	}

	tokens, iTokenIndex, currentRule, err := ruleRO.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("%s: Unable to find next token - %+v", err.Error(), currentRule)
	}

	token := tokens[0]     // preserve this token for switch{} block
	newTail := new(TChain) // append it to the tail of the existing chain
	if CLogLevel > CLogLevelInfo {
		log.Printf("\t\t\tChain Rule:Token='%s',Depth=%d:%+v(Statements:%d)", token, currentRule.Depth, currentRule.Tokens, len(currentRule.SubStatement))
	}

	switch token {
	case CTokenType:
		ret, err := currentRule.parseChainType(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenType, ret.ToString())
			}
		}
	case CTokenChainHook:
		log.Panicf("Token '%s' encountered without keyword 'type' (in %+v)", tokens, currentRule)
	case CTokenChainPriority:
		log.Panicf("Token '%s' encountered without keyword 'type' (in %+v)", tokens, currentRule)
	case CTokenChainPolicy:
		p, err := currentRule.parseDefaultPolicy(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		}
		// try to locate existing ChainType and set that Policy if not set yet...
		newTail.Rule = p

	case CTokenMatchIP:
		ret, err := currentRule.parsePayloadIp(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchIP, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchIP6:
		ret, err := currentRule.parsePayloadIp6(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchIP6, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchTCP:
		ret, err := currentRule.parsePayloadTcp(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchTCP, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchUDP:
		ret, err := currentRule.parsePayloadUdp(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchUDP, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchUDPLite:
		ret, err := currentRule.parsePayloadUdpLite(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchUDPLite, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchSCTP:
		ret, err := currentRule.parsePayloadSctp(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchSCTP, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchDCCP:
		ret, err := currentRule.parsePayloadDccp(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchDCCP, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchAH:
		ret, err := currentRule.parsePayloadAh(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchAH, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchESP:
		ret, err := currentRule.parsePayloadEsp(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchESP, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchComp:
		ret, err := currentRule.parsePayloadIpComp(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchComp, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchICMP:
		ret, err := currentRule.parsePayloadIcmp(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchICMP, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchICMPv6:
		ret, err := currentRule.parsePayloadIcmpv6(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchICMPv6, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchEther:
		ret, err := currentRule.parsePayloadEther(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchEther, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchDST:
		ret, err := currentRule.parsePayloadDst(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchDST, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchFrag:
		ret, err := currentRule.parsePayloadFrag(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchFrag, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchHBH:
		ret, err := currentRule.parsePayloadHbh(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchHBH, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchMH:
		ret, err := currentRule.parsePayloadMh(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchMH, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchRT:
		ret, err := currentRule.parsePayloadRt(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchRT, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchVLAN:
		ret, err := currentRule.parsePayloadVlan(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchVLAN, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchARP:
		ret, err := currentRule.parsePayloadArp(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchARP, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchCT:
		ret, err := currentRule.parseConnTrack(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s", CTokenMatchCT, ret.Expr.TokensToString())
			}
		}
	case CTokenMatchMeta:
		ret, err := currentRule.parseMeta(iTokenIndexRO)
		if err != nil {
			log.Panic(err)
		} else {
			newTail.Rule = ret
			if CLogLevel > CLogLevelInfo {
				log.Printf("\t\t\t\t* [%s]Parsed -> %s (%s)", CTokenMatchMeta, ret.Expr.TokensToString(), TokensToString(newTail.GetTokens()))
			}
		}
	default:
		{
			// first, check if it is of 'meta' tokens, which can be without it (i.e. 'iif lo accept')
			if currentRule.isMetaRule(iTokenIndexRO) {
				// parse for meta
				ret, err := currentRule.parseMeta(iTokenIndexRO)
				if err != nil {
					log.Panic(err)
				} else {
					newTail.Rule = ret
					if CLogLevel > CLogLevelInfo {
						log.Printf("\t\t\t\t* [default:meta]Parsed -> %s (%s)", ret.Expr.TokensToString(), TokensToString(newTail.GetTokens()))
					}
				}
			} else if currentRule.isCounterRule(iTokenIndexRO) {
				// parse for counter
				ret, err := currentRule.parseCounter(iTokenIndexRO)
				if err != nil {
					log.Panic(err)
				} else {
					newTail.Rule = ret
					if CLogLevel > CLogLevelInfo {
						log.Printf("\t\t\t\t* [default:counter]:Parsed -> %s", ret.Expr.TokensToString())
					}
				}
			} else {
				// meta parsed as nil, so assume it's unknown
				log.Panicf("Unhandled chain Rule '%v' (in '%+v') - TokenIndex=%d", tokens, currentRule, iTokenIndex)
			}
		}
	}
	// add it to this tail
	if newTail != nil {
		thisPChainHead.AppendChain(newTail)
	} else if err == nil {
		err = fmt.Errorf("Unable to parse chain rule expression %+v", ruleRO)
	}
	//log.Printf("# New rule: %+v\n\n", newTail.Rule.SRule)
	return err
}

// type <type> hook <hook> [device <device>] priority <priority> \; [policy <policy> \;]
func (rule *TTextStatement) parseChainType(iTokenIndexRO uint16) (*TRuleType, error) {
	var retExpr TRuleType
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("%s: Unable to find next token - %+v", err.Error(), rule)
	}

	for {
		switch tokens[0] {
		case CTokenType:
			retExpr.Type = TExprTypeInfo{Type: tokens[0], Depth: rule.Depth}
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			switch TChainType(tokens[0]) {
			case CChainTypeFilter:
				retExpr.AppendTokens(tokens)
				retExpr.ChainType = CChainTypeFilter
			case CChainTypeRoute:
				retExpr.AppendTokens(tokens)
				retExpr.ChainType = CChainTypeRoute
			case CChainTypeNat:
				retExpr.ChainType = CChainTypeNat
			default:
				log.Panicf("Unkonwn chain Type '%v' (%+v)", tokens, rule)
			}

		case CTokenChainHook:
			retExpr.AppendTokens(tokens)
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retExpr.Hook = THookName(tokens[0])
			retExpr.AppendTokens(tokens)

		case CTokenChainDevice:
			retExpr.AppendTokens(tokens)
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retExpr.Device = tokens[0]
			retExpr.AppendTokens(tokens)

		case CTokenChainPriority:
			retExpr.AppendTokens(tokens)
			tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			isNum, n := tokens[0].tokenToInt()
			if isNum {
				retExpr.Priority = Tpriority(n[0][0])
				retExpr.AppendTokens(tokens)
			} else {
				log.Panicf("Unable to convert '%v' to int value for Priority", tokens)
			}

		case CTokenChainPolicy:
			retExpr.AppendTokens(tokens)
			p, err := currentRule.parseDefaultPolicy(iTokenIndex) // inc iTokenIndex here so getNextToken() below can test or do we assume policy is as-is?
			if err != nil {
				log.Panicf("Unable to find next token - %+v", rule)
			}
			retExpr.Policy = p
			retExpr.AppendTokens(tokens)
		} // switch

		// prepare for next token for the swtich() to process
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			err = nil // return success
			break
		}
	} // for
	return &retExpr, err
}
