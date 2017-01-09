package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Ether
ether match
	saddr <mac address>	Source mac address
		ether saddr 00:0f:54:0c:11:04
	type <type>
		ether type vlan
*/
