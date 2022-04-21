package neo3

import (
	"crypto/ecdsa"
	"sort"
)

func SortPublicKeys(list []*ecdsa.PublicKey) []*ecdsa.PublicKey {
	pl := publicKeyList(list)
	sort.Sort(pl)
	return pl
}

type publicKeyList []*ecdsa.PublicKey

func (this publicKeyList) Len() int {
	return len(this)
}

func (this publicKeyList) Less(i, j int) bool {
	va, vb := this[i], this[j]
	cmp := va.X.Cmp(vb.X)
	if cmp != 0 {
		return cmp < 0
	}
	cmp = va.Y.Cmp(vb.Y)
	return cmp < 0
}

func (this publicKeyList) Swap(i, j int) {
	this[i], this[j] = this[j], this[i]
}
