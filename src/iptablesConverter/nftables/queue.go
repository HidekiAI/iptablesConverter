package nftables

import (
	"log"
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
	//EQ      TEquate
	Verdict TStatementVerdict
	Counter TStatementCounter
	Tokens  []TToken
}

func parseStatementQueue(rule *TTextStatement, iTokenIndexRO uint16) (TStatementQueue, error) {
	var retExpr TStatementQueue
	err, iTokenIndex, tokens, currentRule := getNextToken(rule, iTokenIndexRO, 1)
	if err != nil {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenStatementQueue {
		retExpr.Tokens = append(retExpr.Tokens, tokens[0])
		err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
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

	// now handle verdicts and counter
	err, _, tokens, _ = getNextToken(currentRule, iTokenIndex, 1)
	if err == nil {
		done := false
		for done == false {
			// verdits usually goes last, so always check 'counter' token first
			if isCounterRule(currentRule, iTokenIndex) {
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				if retExpr.Counter, err = parseCounter(currentRule, iTokenIndex); err == nil {
					// skip forward to next token
					err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
					if (err != nil) || (currentRule == nil) {
						err = nil // we're done
						done = true
						break
					}
				}
			} else if isVerdict(currentRule, iTokenIndex) {
				retExpr.Tokens = append(retExpr.Tokens, tokens[0])
				if retExpr.Verdict, err = parseVerdict(currentRule, iTokenIndex); err == nil {
					// skip forward to next token
					err, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
					if (err != nil) || (currentRule == nil) {
						err = nil // we're done
						done = true
						break
					}
				}
			} else {
				err = nil // we're done
				done = true
				break
			}
		}
	} else {
		err = nil // we're done
	}
	return retExpr, err
}
