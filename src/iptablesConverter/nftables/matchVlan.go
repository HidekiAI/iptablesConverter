package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Vlan
vlan match
	id <value>	Vlan tag ID
		vlan id 4094
		vlan id 0
	cfi <value>
		vlan cfi 0
		vlan cfi 1
	pcp <value>
		vlan pcp 7
		vlan pcp 3

*/
