package nftables

import (
	"fmt"
	"log"
	"path/filepath"
	"runtime"
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
	CVerdictAccept   TToken = "accept"
	CVerdictDrop     TToken = "drop"
	CVerdictQueue    TToken = "queue"
	CVerdictContinue TToken = "continue"
	CVerdictReturn   TToken = "return"
	CVerdictJump     TToken = "jump" // requires TChainName
	CVerdictGoto     TToken = "goto" // requires TChainName
)

// {accept | drop | queue | continue | return}
// {jump | goto} {chain}
type TStatementVerdict struct {
	Expr TChainedExpressions

	//Verdict TVerdict   // i.e. "accept", "drop", "goto", "jump"
	//Chain   TChainName // only used by jump | goto
}

func IsVerdict(t TToken) bool {
	caller := ""
	// Caller(1) means the callee of this method (skip 1 stack)
	if _, f, ln, ok := runtime.Caller(1); ok {
		_, fn := filepath.Split(f)
		caller = fmt.Sprintf("%s:%d", fn, ln)
	}
	switch t {
	case CVerdictAccept, CVerdictContinue, CVerdictDrop, CVerdictQueue, CVerdictReturn:
		if CLogLevel > CLogLevelDebug {
			log.Printf("\t\t#%s: IsVerdict(%s): true", caller, t)
		}
		return true
	case CVerdictGoto, CVerdictJump:
		// TODO: make sure the token that follows exists (we don't track chainName so cannot verify, just make sure there is somewhere it can jump/goto)
		if CLogLevel > CLogLevelDebug {
			log.Printf("\t\t#%s: IsVerdict(%s): true", caller, t)
		}
		return true
	}
	if CLogLevel > CLogLevelDebug {
		log.Printf("\t\t#%s: IsVerdict(%s): false", caller, t)
	}
	return false
}
func (rule *TTextStatement) isVerdict(iTokenIndexRO uint16) bool {
	caller := ""
	// Caller(1) means the callee of this method (skip 1 stack)
	if _, f, ln, ok := runtime.Caller(1); ok {
		_, fn := filepath.Split(f)
		caller = fmt.Sprintf("%s:%d", fn, ln)
	}
	tokens, _, _, err := rule.getNextToken(uint16(iTokenIndexRO), 1, true)
	if CLogLevel > CLogLevelDebug {
		log.Printf("\t#%s: Calling IsVerdict(%v) @ Index=%d", caller, tokens, iTokenIndexRO)
	}
	if err != nil {
		log.Panicf("%s: Unable to find next token - %+v", caller, rule)
	}
	return IsVerdict(tokens[0])
}

// parse for default policy (verdicts for the entire chain)
func (rule *TTextStatement) parseDefaultPolicy(iTokenIndexRO uint16) (*TVerdict, error) {
	var retExpr TVerdict
	if len(rule.Tokens) < 2 {
		log.Panicf("Expected at least 2 tokens for 'policy' (in %+v)", rule)
	}
	// policy <policy>
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenChainPolicy {
		//ret.Tokens = append(ret.Tokens, tokens[0])
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	} else {
		log.Panicf("Expected token '%v' but encountered '%v' instead", CTokenChainPolicy, tokens)
	}

	if IsVerdict(tokens[0]) == false {
		log.Panicf("Expression statement '%+v' is not a verdict", rule.Tokens)
	}
	retExpr.Type = TExprTypeInfo{Type: tokens[0], Depth: 0}
	return &retExpr, err
}

// Calling methods should make sure to first call IsVerdict() so that they won't get a panic
func (rule *TTextStatement) parseVerdict(iTokenIndexRO uint16) (*TStatementVerdict, error) {
	caller := ""
	// Caller(1) means the callee of this method (skip 1 stack)
	if _, f, ln, ok := runtime.Caller(1); ok {
		_, fn := filepath.Split(f)
		caller = fmt.Sprintf("%s:%d", fn, ln)
	}
	var retExpr TStatementVerdict
	if rule == nil {
		return &retExpr, fmt.Errorf("%s: Rule expression passed is nil", caller)
	}

	if (len(rule.Tokens) == 0) || (rule.Tokens[0] == "") || (iTokenIndexRO > uint16(len(rule.Tokens))) {
		log.Panicf("%s: There are no Tokens associated to rule:%+v", caller, rule)
	}
	tokens, _, _, err := rule.getNextToken(uint16(iTokenIndexRO), 1, true)
	v := tokens[0]
	if IsVerdict(tokens[0]) == false {
		log.Panicf("%s: Expression '%+v' is not a verdict (%+v)", caller, tokens, rule)
	}
	retExpr.Expr.SetType(v, rule.Depth)

	if CLogLevel > CLogLevelInfo {
		log.Printf("\t#%s: Parsing verdict '%+v' (this: %+v)", caller, rule.Tokens, rule)
	}

	switch v {
	case CVerdictAccept, CVerdictContinue, CVerdictDrop, CVerdictQueue, CVerdictReturn:
		retExpr.Expr.Append(v)
	case CVerdictGoto, CVerdictJump:
		retExpr.Expr.Append(v)
		tokens, _, _, nextErr := rule.getNextToken(iTokenIndexRO, 1, true)
		if nextErr != nil {
			log.Panicf("%s: Expected verdict to follow the token '%s' but instead found '%s' - %+v", caller, v, tokens[0], rule)
			err = nextErr
		}
		retExpr.Expr.Append(TChainName(tokens[0]))
		retExpr.Expr.SetSubType(tokens[0])
	default:
		log.Panicf("Unhandled verdict '%s' (in %+v)", v, rule)
	}

	return &retExpr, err
}
