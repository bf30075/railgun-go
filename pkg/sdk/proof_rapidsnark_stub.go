//go:build !rapidsnark

package sdk

import (
	"fmt"
	"net/http"

	railproof "github.com/bf30075/railgun-go/pkg/proof"
)

// NewRapidsnarkProver 报告 rapidsnark 需要启用 rapidsnark build tag。
func NewRapidsnarkProver(ProofConfig, *http.Client) (*railproof.Prover, error) {
	return nil, fmt.Errorf("rapidsnark prover requires the rapidsnark build tag")
}
