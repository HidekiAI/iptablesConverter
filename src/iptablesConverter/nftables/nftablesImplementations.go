package nftables

import (
	"log"
	"os"
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
	for _, ts := range tables {
		deserializeRecursive(ts, &ret, nil, CAddressFamilyUndefined, nil)
	}
	return ret
}
func deserializeRecursive(ts *TTextStatement, nft *Nftables, pCurrentTable *TTable, caf TAddressFamily, pCurrentChain *TChain) {
	// first, parse the tokens - NOTE that what we are interested in are
	// are statements that have AT LEAST 2 tokens.  Statements which only
	// have one is usually comments ("#"), beginning of statements ("{"),
	// closing of statements ("}"), or new line (";").  Rest are usually
	// based on two or more (i.e. 'table INPUT')
	// It is also because there seems to be a bug (language GO or the parser
	// code itself) which Tokens[] would have length of 1, and contains
	// series of 0x0000's which I cannot seem to get around it at the
	// moment...
	if len(ts.Tokens) > 1 {
		if caf == CAddressFamilyUndefined {
			// assume default
			caf = CAddressFamilyIP
		}

		token := TToken(strings.ToLower(strings.TrimSpace(ts.Tokens[0])))
		switch token {
		case CTokenTable:
			t := parseTable(ts.Tokens)
			pCurrentTable = nft.AddTable(t.Family, t.Name)
			caf = t.Family

		case CTokenChain:
			c := parseChain(ts.Tokens)
			pCurrentChain = pCurrentTable.RegisterChain(c.Name)

		case CTokenSC, CTokenOB, CTokenCB, CTokenHash, "":
			// do nothing

		default:
			// if it is not 'table' or 'chain' tokens, it must be rules to the TChain
			if pCurrentTable == nil {
				log.Panicf("Unable to deal with nil Table for tokens:\n\t%+v (len: %d)\n\n", ts.Tokens, len(ts.Tokens))
			}
			if pCurrentChain == nil {
				log.Panicf("Unable to deal with nil Chain for tokens:\n\t%+v (len: %d)\n\n", ts.Tokens, len(ts.Tokens))
			}
			sr := stripRule(ts.Tokens)
			pCurrentChain.ChainRule(CRuleCommandAdd, sr)
		}
	}

	// next, parse all statements for the token
	for _, tss := range ts.SubStatement {
		deserializeRecursive(tss, nft, pCurrentTable, caf, pCurrentChain)
	}
}

func stripRule(slist []string) []string {
	var sr []string
	for _, s := range slist {
		if s == "{" || s == "}" || s == ";" {
			continue
		}
		sr = append(sr, s)
	}
	return sr
}
func parseTable(slist []string) *TTable {
	// Example: 'table ip filter', 'table ip6 nat'
	sr := stripRule(slist)
	if len(sr) < 2 || len(sr) > 3 {
		log.Panicf("table must have at least 1 parameter (if family missing, defaults to 'ip' family), i.e. 'table ip filter', 'table ip6 nat' (len:%d, '%+v')", len(sr), slist)
	}
	var n TTableName
	var f TAddressFamily
	if len(sr) == 2 {
		f = CAddressFamilyIP
		n = TTableName(sr[1])
	} else {
		f = TAddressFamily(sr[1])
		n = TTableName(sr[2])
	}
	table := TTable{Name: n}
	switch TAddressFamily(f) {
	case CAddressFamilyIP:
		table.Family = CAddressFamilyIP
	case CAddressFamilyIP6:
		table.Family = CAddressFamilyIP6
	default:
		log.Panicf("Unhandled Address Family: '%s' (in '%+v')", sr[1], slist)
	}
	return &table
}

func parseChain(slist []string) *TChain {
	// Example: 'chain input {...}'
	sr := stripRule(slist)
	if len(sr) != 2 {
		log.Panicf("Chain must have a chainname associated to it; i.e. 'chain INPUT' (in '%+v')", slist)
	}
	chain := TChain{Name: TChainName(sr[1])}
	return &chain
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
		t := TTable{
			Name:   tn,
			Family: f,
		}
		un := MakeUniqueName(f, tn)
		if (*thisPNft).Tables == nil {
			(*thisPNft).Tables = make(map[TUniqueTableName]TTable)
		}
		(*thisPNft).Tables[un] = t
		pT = &t
	}
	return pT
}

func (thisROTable TTable) FindChain(cn TChainName) *TChain {
	for _, j := range thisROTable.Chains {
		if j.Name == cn {
			// found the Chain to be already registered
			return &j
		}
	}
	return nil
}

// The syntax to add base chains is the following:
//	% nft add chain [<family>] <table-name> <chain-name> { type <type> hook <hook> priority <value> \; }
func (thisPTable *TTable) RegisterChainWithRule(cn TChainName, ct TChainType, h THookName, p Tpriority) *TChain {
	foundChain := thisPTable.FindChain(cn)
	if foundChain == nil {
		// Chain doesn't exist
		foundChain = new(TChain)
		foundChain.Name = cn
		thisPTable.Chains = append(thisPTable.Chains, *foundChain)
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
		found.Name = cn
		thisPTable.Chains = append(thisPTable.Chains, *found)
	}
	return found
}

// ChainRule expects tokenized list of string so that it does not have to do the parsing of
// quoted strings (i.e. [comment] ["this is a comment, so it's 2 tokens"])
func (thisPChain *TChain) ChainRule(cmd TRuleCommand, rule []string) bool {
	processed := false
	switch cmd {
	case CRuleCommandAdd:
		{
			processed = thisPChain.AddRule(rule)
		}
	case CRuleCommandInsert:
		{
			processed = thisPChain.InsertRule(rule)
			log.Panicf("Chain command '%s' currently not supported!\n", cmd)
		}
	case CRuleCommandDelete:
		{
			processed = thisPChain.DeleteRule(rule)
			log.Panicf("Chain command '%s' currently not supported!\n", cmd)
		}
	}

	return processed
}

func (thisPChain *TChain) AddRule(rule []string) bool {
	added := false

	return added
}

func (thisPChain *TChain) InsertRule(rule []string) bool {
	inserted := false

	log.Panic("InsertRule method currently unsupported!")
	return inserted
}
func (thisPChain *TChain) DeleteRule(rule []string) bool {
	deleted := false

	log.Panic("DeleteRule method currently unsupported!")
	return deleted
}
