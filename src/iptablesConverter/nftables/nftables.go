package nftables

type Nftables struct {
	X, Y float64
}

func Read(path string) Nftables {
	ret := Nftables{}
	return ret
}
