package nftables

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
