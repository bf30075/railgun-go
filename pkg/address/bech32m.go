package address

import (
	"fmt"
	"strings"
)

const bech32mCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
const bech32mChecksumConstant = 0x2bc830a3

var bech32mCharsetRev = func() map[rune]int {
	out := make(map[rune]int, len(bech32mCharset))
	for i, r := range bech32mCharset {
		out[r] = i
	}
	return out
}()

func bech32mEncode(hrp string, data []byte) (string, error) {
	words, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	checksum := createChecksum(hrp, words)
	var out strings.Builder
	out.WriteString(hrp)
	out.WriteByte('1')
	for _, word := range append(words, checksum...) {
		if int(word) >= len(bech32mCharset) {
			return "", fmt.Errorf("invalid bech32 word")
		}
		out.WriteByte(bech32mCharset[word])
	}
	if out.Len() != AddressLengthLimit {
		return "", fmt.Errorf("invalid encoded address length %d", out.Len())
	}
	return out.String(), nil
}

func bech32mDecode(value string) (string, []byte, error) {
	if value != strings.ToLower(value) {
		return "", nil, fmt.Errorf("mixed-case bech32 string")
	}
	separator := strings.LastIndexByte(value, '1')
	if separator < 1 || separator+7 > len(value) {
		return "", nil, fmt.Errorf("invalid bech32 separator")
	}
	hrp := value[:separator]
	rawWords := value[separator+1:]
	words := make([]byte, len(rawWords))
	for i, r := range rawWords {
		v, ok := bech32mCharsetRev[r]
		if !ok {
			return "", nil, fmt.Errorf("invalid bech32 character")
		}
		words[i] = byte(v)
	}
	if !verifyChecksum(hrp, words) {
		return "", nil, fmt.Errorf("invalid checksum")
	}
	payloadWords := words[:len(words)-6]
	payload, err := convertBits(payloadWords, 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, payload, nil
}

func hrpExpand(hrp string) []byte {
	out := make([]byte, 0, len(hrp)*2+1)
	for _, c := range hrp {
		out = append(out, byte(c>>5))
	}
	out = append(out, 0)
	for _, c := range hrp {
		out = append(out, byte(c&31))
	}
	return out
}

func polymod(values []byte) int {
	chk := 1
	generator := [5]int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	for _, value := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ int(value)
		for i := 0; i < 5; i++ {
			if (top>>i)&1 == 1 {
				chk ^= generator[i]
			}
		}
	}
	return chk
}

func createChecksum(hrp string, data []byte) []byte {
	values := append(hrpExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := polymod(values) ^ bech32mChecksumConstant
	out := make([]byte, 6)
	for i := 0; i < 6; i++ {
		out[i] = byte((mod >> uint(5*(5-i))) & 31)
	}
	return out
}

func verifyChecksum(hrp string, words []byte) bool {
	values := append(hrpExpand(hrp), words...)
	return polymod(values) == bech32mChecksumConstant
}

func convertBits(data []byte, fromBits uint, toBits uint, pad bool) ([]byte, error) {
	acc := 0
	bits := uint(0)
	maxValue := (1 << toBits) - 1
	maxAcc := (1 << (fromBits + toBits - 1)) - 1
	out := make([]byte, 0, len(data)*int(fromBits)/int(toBits))
	for _, value := range data {
		if int(value)>>fromBits != 0 {
			return nil, fmt.Errorf("invalid data range")
		}
		acc = ((acc << fromBits) | int(value)) & maxAcc
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte((acc>>bits)&maxValue))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<(toBits-bits))&maxValue))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxValue) != 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	return out, nil
}
