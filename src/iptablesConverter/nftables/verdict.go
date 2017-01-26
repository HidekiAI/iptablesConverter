package nftables

import (
	"log"
)

// statement is the action performed when the packet match the rule. It could be terminal and non-terminal. In a certain rule we can consider several non-terminal statements but only a single terminal statement.
// See: https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*

Verdict statements
The verdict statement alters control flow in the ruleset and issues policy decisions for packets. The valid verdict statements are:
	* accept: Accept the packet and stop the remain rules evaluation.
	* drop: Drop the packet and stop the remain rules evaluation.
	* queue: Queue the packet to userspace and stop the remain rules evaluation.
	* continue: Continue the ruleset evaluation with the next rule.
	* return: Return from the current chain and continue at the next rule of the last chain. In a base chain it is equivalent to accept
	* jump <chain>: Continue at the first rule of <chain>. It will continue at the next rule after a return statement is issued
	* goto <chain>: Similar to jump, but after the new chain the evaluation will continue at the last chain instead of the one containing the goto statement
*/
// Statements represent actions to be performed. They can alter control flow (return, jump to a different chain, accept or drop the packet) or can perform actions, such as logging, rejecting a packet, etc.
// Statements exist in two kinds. Terminal statements unconditionally terminate evaluation of the current rule, non-terminal statements either only conditionally or never terminate evaluation of the current rule, in other words,
// they are passive from the ruleset evaluation perspective. There can be an arbitrary amount of non-terminal statements in a rule, but only a single terminal statement as the final statement.

const (
	CVerdictAccept   TVerdict = "accept"
	CVerdictDrop     TVerdict = "drop"
	CVerdictQueue    TVerdict = "queue"
	CVerdictContinue TVerdict = "continue"
	CVerdictReturn   TVerdict = "return"
	CVerdictJump     TVerdict = "jump" // requires TChainName
	CVerdictGoto     TVerdict = "goto" // requires TChainName
)

// {accept | drop | queue | continue | return}
// {jump | goto} {chain}
type TStatementVerdict struct {
	Verdict TVerdict   // i.e. "accept", "drop", "goto", "jump"
	Chain   TChainName // only used by jump | goto

	//EQ      TEquate
	Tokens []TToken
}

func IsVerdict(t TToken) bool {
	switch TVerdict(t) {
	case CVerdictAccept, CVerdictContinue, CVerdictDrop, CVerdictQueue, CVerdictReturn:
		return true
	case CVerdictGoto, CVerdictJump:
		// TODO: make sure the token that follows exists (we don't track chainName so cannot verify, just make sure there is somewhere it can jump/goto)
		return true
	}
	return false
}
func isVerdict(rule *TTextStatement, iTokenIndexRO uint16) bool {
	err, _, tokens, _ := getNextToken(rule, uint16(iTokenIndexRO), 1)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	return IsVerdict(tokens[0])
}

// parse for default policy (verdicts for the entire chain)
func parseDefaultPolicy(rule *TTextStatement, iTokenIndexRO uint16) (TVerdict, error) {
	var retExpr TVerdict
	if len(rule.Tokens) < 2 {
		log.Panicf("Expected at least 2 tokens for 'policy' (in %+v)", rule)
	}
	// policy <policy>
	err, iTokenIndex, tokens, currentRule := getNextToken(rule, iTokenIndexRO, 1)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenChainPolicy {
		//ret.Tokens = append(ret.Tokens, tokens[0])
		err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	} else {
		log.Panicf("Expected token '%v' but encountered '%v' instead", CTokenChainPolicy, tokens)
	}

	if IsVerdict(tokens[0]) == false {
		log.Panicf("Expression statement '%+v' is not a verdict", rule.Tokens)
	}
	retExpr = TVerdict(tokens[0])
	return retExpr, err
}

// Calling methods should make sure to first call IsVerdict() so that they won't get a panic
func parseVerdict(rule *TTextStatement, iTokenIndexRO uint16) (TStatementVerdict, error) {
	var retExpr TStatementVerdict
	if (rule != nil) && (len(rule.Tokens) == 0) || (rule.Tokens[0] == "") {
		log.Panicf("There are no Tokens associated to rule:%+v", rule)
	}

	err, iTokenIndex, tokens, currentRule := getNextToken(rule, uint16(iTokenIndexRO), 1)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if IsVerdict(tokens[0]) == false {
		log.Panicf("Expression statement '%+v' is not a verdict", rule.Tokens)
	}
	retExpr.Tokens = append(retExpr.Tokens, tokens[0])

	if logLevel > 1 {
		log.Printf("\tParsing verdict '%+v' (this: %+v)", rule.Tokens, rule)
	}

	v := TVerdict(tokens[0])
	switch v {
	case CVerdictAccept, CVerdictContinue, CVerdictDrop, CVerdictQueue, CVerdictReturn:
		retExpr.Verdict = v
	case CVerdictGoto, CVerdictJump:
		retExpr.Verdict = v
		if err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1); err != nil {
			log.Panicf("Expected verdict to follow the token '%s' but instead found '%s' - %+v", v, tokens[0], rule)
		}
		retExpr.Chain = TChainName(tokens[0])
		retExpr.Tokens = append(retExpr.Tokens, tokens[0])
	default:
		log.Panicf("Unhandled verdict '%s' (in %+v)", v, rule)
	}

	return retExpr, err
}
