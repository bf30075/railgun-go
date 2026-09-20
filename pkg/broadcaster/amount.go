package broadcaster

import (
	"math/big"
	"time"
)

func timeNowMS() int64 {
	return time.Now().UnixMilli()
}

func newAmount(value string) (*big.Int, bool) {
	n, ok := new(big.Int).SetString(value, 10)
	return n, ok
}

func mulPct(amount *big.Int, pct float64) *big.Int {
	out := new(big.Int).Mul(amount, big.NewInt(int64(pct*100)))
	return out.Div(out, big.NewInt(100))
}

func subAmount(a, b *big.Int) *big.Int {
	return new(big.Int).Sub(a, b)
}

func addAmount(a, b *big.Int) *big.Int {
	return new(big.Int).Add(a, b)
}

func cmpAmount(a, b *big.Int) int {
	return a.Cmp(b)
}
