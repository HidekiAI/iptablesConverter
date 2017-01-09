package nftables

// Matches are clues used to access to certain packet infromation and reate filters according to them.
// See https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
/*
Esp
esp match
	spi <value>
		esp spi 111
		esp spi != 111-222
		esp spi {111, 122 }
	sequence <sequence>	Sequence Number
		esp sequence 123
		esp sequence {23, 25, 33}
		esp sequence != 23-33

*/
