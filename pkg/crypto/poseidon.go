package railcrypto

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
)

//go:embed poseidon_constants_opt.json
var poseidonConstantsJSON []byte

const nRoundsF = 8

var nRoundsP = []int{56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68}

type poseidonConstantsRaw struct {
	C [][]string   `json:"C"`
	S [][]string   `json:"S"`
	M [][][]string `json:"M"`
	P [][][]string `json:"P"`
}

type poseidonConstants struct {
	C [][]*big.Int
	S [][]*big.Int
	M [][][]*big.Int
	P [][][]*big.Int
}

var (
	poseidonConstantsOnce sync.Once
	poseidonConstantsData poseidonConstants
	poseidonConstantsErr  error
)

func Poseidon(inputs ...*big.Int) (*big.Int, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("poseidon requires at least one input")
	}
	if len(inputs) > len(nRoundsP) {
		return nil, fmt.Errorf("poseidon supports at most %d inputs", len(nRoundsP))
	}

	constants, err := loadPoseidonConstants()
	if err != nil {
		return nil, err
	}

	t := len(inputs) + 1
	nPartialRounds := nRoundsP[t-2]
	c := constants.C[t-2]
	s := constants.S[t-2]
	m := constants.M[t-2]
	p := constants.P[t-2]

	state := make([]*big.Int, 0, t)
	state = append(state, big.NewInt(0))
	for _, input := range inputs {
		state = append(state, field(input))
	}

	arc(state, c[0:t])
	for r := 0; r < nRoundsF/2; r++ {
		if r == nRoundsF/2-1 {
			fullRound(state, c[(r+1)*t:(r+2)*t], p)
		} else {
			fullRound(state, c[(r+1)*t:(r+2)*t], m)
		}
	}

	for r := 0; r < nPartialRounds; r++ {
		state[0] = exp5(state[0])
		state[0] = add(state[0], c[(nRoundsF/2+1)*t+r])

		s0 := big.NewInt(0)
		for i := 0; i < t; i++ {
			s0 = add(s0, mul(s[(t*2-1)*r+i], state[i]))
		}

		for k := 1; k < t; k++ {
			state[k] = add(state[k], mul(state[0], s[(t*2-1)*r+t+k-1]))
		}
		state[0] = s0
	}

	for r := 0; r < nRoundsF/2-1; r++ {
		start := (nRoundsF/2+1)*t + nPartialRounds + r*t
		fullRound(state, c[start:start+t], m)
	}

	sbox(state)
	mix(state, m)
	return new(big.Int).Set(state[0]), nil
}

func PoseidonHex(inputs ...string) (string, error) {
	bigInputs := make([]*big.Int, len(inputs))
	for i, input := range inputs {
		n, err := HexToBigInt(input)
		if err != nil {
			return "", err
		}
		bigInputs[i] = n
	}
	hash, err := Poseidon(bigInputs...)
	if err != nil {
		return "", err
	}
	return BigIntToHex(hash, 32, false)
}

func loadPoseidonConstants() (poseidonConstants, error) {
	poseidonConstantsOnce.Do(func() {
		var raw poseidonConstantsRaw
		if err := json.Unmarshal(poseidonConstantsJSON, &raw); err != nil {
			poseidonConstantsErr = err
			return
		}
		poseidonConstantsData.C, poseidonConstantsErr = parseConstantRows(raw.C)
		if poseidonConstantsErr != nil {
			return
		}
		poseidonConstantsData.S, poseidonConstantsErr = parseConstantRows(raw.S)
		if poseidonConstantsErr != nil {
			return
		}
		poseidonConstantsData.M, poseidonConstantsErr = parseConstantMatrices(raw.M)
		if poseidonConstantsErr != nil {
			return
		}
		poseidonConstantsData.P, poseidonConstantsErr = parseConstantMatrices(raw.P)
	})
	return poseidonConstantsData, poseidonConstantsErr
}

func parseConstantRows(rows [][]string) ([][]*big.Int, error) {
	out := make([][]*big.Int, len(rows))
	for i, row := range rows {
		out[i] = make([]*big.Int, len(row))
		for j, value := range row {
			n, err := HexToBigInt(value)
			if err != nil {
				return nil, fmt.Errorf("constant row %d item %d: %w", i, j, err)
			}
			out[i][j] = field(n)
		}
	}
	return out, nil
}

func parseConstantMatrices(matrices [][][]string) ([][][]*big.Int, error) {
	out := make([][][]*big.Int, len(matrices))
	for i, matrix := range matrices {
		out[i] = make([][]*big.Int, len(matrix))
		for j, row := range matrix {
			out[i][j] = make([]*big.Int, len(row))
			for k, value := range row {
				n, err := HexToBigInt(value)
				if err != nil {
					return nil, fmt.Errorf("constant matrix %d row %d item %d: %w", i, j, k, err)
				}
				out[i][j][k] = field(n)
			}
		}
	}
	return out, nil
}

func fullRound(state []*big.Int, c []*big.Int, m [][]*big.Int) {
	sbox(state)
	arc(state, c)
	mix(state, m)
}

func arc(state []*big.Int, c []*big.Int) {
	for i := range state {
		state[i] = add(state[i], c[i])
	}
}

func sbox(state []*big.Int) {
	for i := range state {
		state[i] = exp5(state[i])
	}
}

func mix(state []*big.Int, m [][]*big.Int) {
	newState := make([]*big.Int, len(state))
	for i := range state {
		lc := big.NewInt(0)
		for j := range state {
			lc = add(lc, mul(m[j][i], state[j]))
		}
		newState[i] = lc
	}
	copy(state, newState)
}

func exp5(value *big.Int) *big.Int {
	return new(big.Int).Exp(field(value), big.NewInt(5), SNARKPrime)
}

func add(left *big.Int, right *big.Int) *big.Int {
	out := new(big.Int).Add(left, right)
	out.Mod(out, SNARKPrime)
	return out
}

func mul(left *big.Int, right *big.Int) *big.Int {
	out := new(big.Int).Mul(left, right)
	out.Mod(out, SNARKPrime)
	return out
}

func field(value *big.Int) *big.Int {
	out := new(big.Int).Set(value)
	out.Mod(out, SNARKPrime)
	if out.Sign() < 0 {
		out.Add(out, SNARKPrime)
	}
	return out
}
