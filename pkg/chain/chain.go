package chain

import "fmt"

type Chain struct {
	Type int    `json:"type"`
	ID   uint64 `json:"id"`
}

var chainsSupportingV3 []Chain

func FullNetworkIDHex(chain Chain) (string, error) {
	if chain.Type < 0 || chain.Type > 255 {
		return "", fmt.Errorf("chain type exceeds uint8")
	}
	if chain.ID >= 1<<56 {
		return "", fmt.Errorf("chain id exceeds uint56")
	}
	return fmt.Sprintf("%02x%014x", chain.Type, chain.ID), nil
}

func FullNetworkIDUint64(chain Chain) (uint64, error) {
	if _, err := FullNetworkIDHex(chain); err != nil {
		return 0, err
	}
	return uint64(chain.Type)<<56 | chain.ID, nil
}

func SupportsV3(chain Chain) bool {
	for _, supportingV3Chain := range chainsSupportingV3 {
		if chain.ID == supportingV3Chain.ID && chain.Type == supportingV3Chain.Type {
			return true
		}
	}
	return false
}

func AssertSupportsV3(chain Chain) error {
	if SupportsV3(chain) {
		return nil
	}
	return fmt.Errorf("Chain does not support V3: %d:%d. Set supportsV3 'true' in loadNetwork.", chain.Type, chain.ID)
}

func AddSupportsV3(chain Chain) {
	if SupportsV3(chain) {
		return
	}
	chainsSupportingV3 = append(chainsSupportingV3, chain)
}
