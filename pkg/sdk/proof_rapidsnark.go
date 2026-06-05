//go:build rapidsnark

package sdk

import (
	"net/http"

	railproof "github.com/bf30075/railgun-go/pkg/proof"
	"github.com/bf30075/railgun-go/pkg/proof/rapidsnark"
)

// NewRapidsnarkProver 创建由 rapidsnark 驱动的 prover。
func NewRapidsnarkProver(config ProofConfig, httpClient *http.Client) (*railproof.Prover, error) {
	return NewProver(config, rapidsnark.New(config.RapidsnarkProverBinary), httpClient)
}
