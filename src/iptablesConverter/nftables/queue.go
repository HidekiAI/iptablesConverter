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
   QUEUE STATEMENT
       This statement passes the packet to userspace using the nfnetlink_queue handler. The packet is put into the queue identified by its 16-bit queue number. Userspace can inspect and modify the packet if desired. Userspace must
       then drop or reinject the packet into the kernel. See libnetfilter_queue documentation for details.

       queue [num queue_number] [bypass]
       queue [num queue_number_from - queue_number_to] [bypass,fanout]

       queue statement values

       ┌──────────────────┬─────────────────────────────────────────────────────┬───────────────────────────┐
       │Value             │ Description                                         │ Type                      │
       ├──────────────────┼─────────────────────────────────────────────────────┼───────────────────────────┤
       │queue_number      │ Sets queue number, default is 0.                    │ unsigned integer (16 bit) │
       ├──────────────────┼─────────────────────────────────────────────────────┼───────────────────────────┤
       │queue_number_from │ Sets initial queue in the range, if fanout is used. │ unsigned integer (16 bit) │
       ├──────────────────┼─────────────────────────────────────────────────────┼───────────────────────────┤
       │queue_number_to   │ Sets closing queue in the range, if fanout is used. │ unsigned integer (16 bit) │
       └──────────────────┴─────────────────────────────────────────────────────┴───────────────────────────┘
       queue statement flags

       ┌───────┬───────────────────────────────────────────────────────────────────────────────┐
       │Flag   │ Description                                                                   │
       ├───────┼───────────────────────────────────────────────────────────────────────────────┤
       │bypass │ Let packets go through if userspace application cannot back off. Before using │
       │       │ this flag, read libnetfilter_queue documentation for performance tuning re‐   │
       │       │ comendations.                                                                 │
       ├───────┼───────────────────────────────────────────────────────────────────────────────┤
       │fanout │ Distribute packets between several queues.                                    │
       └───────┴───────────────────────────────────────────────────────────────────────────────┘

queue statement
	num <value> <scheduler>
		queue
		queue num 2
		queue num 2-3
		queue num 4-5 fanout bypass
		queue num 4-5 fanout
		queue num 4-5 bypass
*/
type TStatementQueue struct {
	Expr TChainedExpressions

	//EQ      *TEquate
	//Verdict *TStatementVerdict
	//Counter *TStatementCounter
}

func (expr *TStatementQueue) HasExpression() bool {
	if expr != nil {
		return (expr.Expr.Expressions != nil) && (len(expr.Expr.Expressions) > 0)
	}
	return false
}
func (expr *TStatementQueue) GetTokens() []TToken {
	var ret []TToken
	if expr.HasExpression() {
		for _, e := range expr.Expr.Expressions {
			switch tExpr := e.(type) {
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

func (rule *TTextStatement) parseStatementQueue(iTokenIndexRO uint16) (*TStatementQueue, error) {
	var retExpr TStatementQueue
	tokens, iTokenIndex, currentRule, err := rule.getNextToken(iTokenIndexRO, 1, true)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenStatementQueue {
		retExpr.Expr.SetType(tokens[0], rule.Depth)
		tokens, iTokenIndex, currentRule, err = currentRule.getNextToken(iTokenIndex, 1, true)
		if err != nil {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'queue' (in %+v)", tokens, rule)
		}
	}

	// now handle verdicts and counter chains
	err = retExpr.Expr.ParseTailChains(currentRule, iTokenIndex)

	return &retExpr, err
}
