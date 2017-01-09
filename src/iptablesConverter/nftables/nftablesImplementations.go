package nftables

import (
	"log"
)

//
func Read(path string) Nftables {
	ret := Nftables{}
	return ret
}

// FindTable attempts to locate table (tn) via inspections to both
// map key as well as the actual Table name
func (thisNft Nftables) FindTable(f TAddressFamily, tn TTableName) (bool, TTable) {
	var ret TTable
	un := MakeUniqueName(f, tn)
	found := false

	// first, do the quick thing, see if TTable.Name matches map key
	if v, ok := thisNft.Tables[un]; ok {
		if v.Name == tn && v.Family == f {
			found = true
			ret = v
		}
	} else {
		// Do not trust the map-Key, walk through the collection for real table name
		for _, v := range thisNft.Tables {
			// key: table name (ignored, since we did not find it from above), value: TTable
			if v.Name == tn && v.Family == f {
				found = true
				ret = v
			}
		}
	}
	return found, ret
}

func MakeUniqueName(f TAddressFamily, tn TTableName) TUniqueTableName {
	return TUniqueTableName(string(f) + "." + string(tn))
}

// AddTable inspects first determines if the table already have a TTable in place,
// and if it does, returns false to indicate to the caller that table was not added
// Normally, if TAddressFamily is not present (i.e. 'nft add table [AddressFamily] TableName')
// then it defaults to 'ip' family, but caller will have to explicitly pass CAddressFamilyIP
func (thisPNft *Nftables) AddTable(f TAddressFamily, tn TTableName) bool {
	found, t := thisPNft.FindTable(f, tn)
	if found == false {
		// create one
		t = TTable{
			Name:   tn,
			Family: f,
		}
		un := MakeUniqueName(f, tn)
		(*thisPNft).Tables[un] = t
	}
	return (found == false)
}

func (thisROTable TTable) FindChain(cn TChainName) bool {
	found := false
	for _, j := range thisROTable.Chains {
		if j.Name == cn {
			// found the Chain to be already registered
			found = true
			break
		}
	}
	return found
}

// The syntax to add base chains is the following:
//	% nft add chain [<family>] <table-name> <chain-name> { type <type> hook <hook> priority <value> \; }
func (thisPTable *TTable) RegisterChainWithRule(cn TChainName, ct TChainType, h THookName, p Tpriority) bool {
	registered := false
	if found := thisPTable.FindChain(cn); !found {
		// Chain doesn't exist
		thisPTable.Chains = append(thisPTable.Chains, TChain{Name: cn})
		registered = true
	}

	return registered
}

// Minimum you need is Family to determine which table to register to, and Name but
// because this is based on TTable (i.e. Family="ip", Table="filter")), we already know which Family
// it belongs to.  Property will need to be added manually
func (thisPTable *TTable) RegisterChain(cn TChainName) bool {
	registered := false
	if found := thisPTable.FindChain(cn); !found {
		// Chain doesn't exist
		thisPTable.Chains = append(thisPTable.Chains, TChain{Name: cn})
		registered = true
	}

	return registered
}

func (thisPChain *TChain) ChainRule(cmd TRuleCommand) bool {
	processed := false
	switch cmd {
	case CRuleCommandAdd:
		{
			//			processed = thisPChain.AddRule(m, s)
		}
	case CRuleCommandInsert:
		{
			processed = thisPChain.InsertRule()
			log.Panicf("Chain command '%s' currently not supported!\n", cmd)
		}
	case CRuleCommandDelete:
		{
			processed = thisPChain.DeleteRule()
			log.Panicf("Chain command '%s' currently not supported!\n", cmd)
		}
	}

	return processed
}

//func (thisPChain *TChain) AddRule(m TMatch, s TStatement) bool {
//	added := false
//
//	return added
//}

func (thisPChain *TChain) InsertRule() bool {
	inserted := false

	log.Panic("InsertRule method currently unsupported!")
	return inserted
}
func (thisPChain *TChain) DeleteRule() bool {
	deleted := false

	log.Panic("DeleteRule method currently unsupported!")
	return deleted
}
