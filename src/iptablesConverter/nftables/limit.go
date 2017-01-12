package nftables

import (
	"log"
)

// statement is the action performed when the packet match the rule. It could be terminal and non-terminal. In a certain rule we can consider several non-terminal statements but only a single terminal statement.
// See: https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
   LIMIT STATEMENT
       limit rate [over] packet_number / {second | minute | hour | day} [burst packet_number packets]
       limit rate [over] byte_number {bytes | kbytes | mbytes} / {second | minute | hour | day | week} [burst byte_number bytes]

       A limit statement matches at a limited rate using a token bucket filter. A rule using this statement will match until this limit is reached. It can be used in combination with the log statement to give limited logging. The over
       keyword, that is optional, makes it match over the specified rate.

       limit statement values

       ┌──────────────┬───────────────────┬───────────────────────────┐
       │Value         │ Description       │ Type                      │
       ├──────────────┼───────────────────┼───────────────────────────┤
       │packet_number │ Number of packets │ unsigned integer (32 bit) │
       ├──────────────┼───────────────────┼───────────────────────────┤
       │byte_number   │ Number of bytes   │ unsigned integer (32 bit) │
       └──────────────┴───────────────────┴───────────────────────────┘


limit statement
	rate [over] <value> <unit> [burst <value> <unit>]	Rate limit
		limit rate 400/minute
		limit rate 400/hour
		limit rate over 40/day
		limit rate over 400/week
		limit rate over 1023/second burst 10 packets
		limit rate 1025 kbytes/second
		limit rate 1023000 mbytes/second
		limit rate 1025 bytes/second burst 512 bytes
		limit rate 1025 kbytes/second burst 1023 kbytes
		limit rate 1025 mbytes/second burst 1025 kbytes
		limit rate 1025000 mbytes/second burst 1023 mbytes
*/
type TStatementLimit struct {
	//EQ      TEquate
	//Verdict TStatementVerdict
	Tokens []TToken
}

func parseStatementLimit(rule *TTextStatement) *TStatementLimit {
	retLimit := new(TStatementLimit)
	haveToken, iTokenIndex, tokens, currentRule := getNextToken(rule, 0, 1)
	if haveToken == false {
		log.Panicf("Unable to find next token - %+v", rule)
	}
	if tokens[0] == CTokenStatementLimit {
		retLimit.Tokens = append(retLimit.Tokens, tokens[0])
		haveToken, iTokenIndex, tokens, currentRule = getNextToken(currentRule, iTokenIndex, 1)
		if haveToken == false {
			log.Panicf("Unable to find next token - %+v", rule)
		}
	}

	switch tokens[0] {
	default:
		{
			log.Panicf("Unhandled token '%v' for 'limit' (in %+v)", tokens, rule)
		}
	}

	log.Panicf("Not implemented: %+v", rule)
	return nil
}
