package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Ah
ah match
	hdrlength <length>	AH header length
		ah hdrlength 11-23
		ah hdrlength != 11-23
		ah hdrlength {11, 23, 44 }
	reserved <value>
		ah reserved 22
		ah reserved != 33-45
		ah reserved {23, 100 }
		ah reserved { 33-55 }
	spi <value>
		ah spi 111
		ah spi != 111-222
		ah spi {111, 122 }
	sequence <sequence>	Sequence Number
		ah sequence 123
		ah sequence {23, 25, 33}
		ah sequence != 23-33

*/
