package broadcaster

import (
	"strings"
)

// DefaultRelayAdaptHistory mirrors upstream NETWORK_CONFIG relayAdaptHistory
// for the chains railgun-go ships example configs for.
func DefaultRelayAdaptHistory() map[string][]string {
	return map[string][]string{
		chainKey(0, 1): {
			"0x22af4EDBeA3De885dDa8f0a0653E6209e44e5B84",
			"0xc3f2C8F9d5F0705De706b1302B7a039e1e11aC88",
			"0x4025ee6512DBbda97049Bcf5AA5D38C54aF6bE8a",
			"0xAc9f360Ae85469B27aEDdEaFC579Ef2d052aD405",
		},
		chainKey(0, 56): {
			"0x20d868C7F1Eb706C46641ADD2f849c5DBf4dB158",
			"0x25f795A8eC8aF7904aa403fF2Cc7205ce683BF52",
			"0x741936fb83DDf324636D3048b3E6bC800B8D9e12",
			"0xF82d00fC51F730F42A00F85E74895a2849ffF2Dd",
		},
		chainKey(0, 137): {
			"0x30D8AD0339e2CF160620589f2DBa1765126A5fDC",
			"0x969eE9AC1E0B5F5Dd781f63A168C52b73062ff86",
			"0xc7FfA542736321A3dd69246d73987566a5486968",
			"0xF82d00fC51F730F42A00F85E74895a2849ffF2Dd",
		},
	}
}

func relayAdaptAllowed(history []string, relayAdapt string) bool {
	if relayAdapt == "" {
		return false
	}
	want := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(relayAdapt, "0x"), "0X"))
	for _, addr := range history {
		got := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(addr, "0x"), "0X"))
		if got == want {
			return true
		}
	}
	return false
}
