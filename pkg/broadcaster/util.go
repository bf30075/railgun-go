package broadcaster

import (
	"strconv"
	"strings"
)

func versionCompare(a, b string) int {
	ap := parseVersionParts(a)
	bp := parseVersionParts(b)
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(ap) {
			av = ap[i]
		}
		if i < len(bp) {
			bv = bp[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func parseVersionParts(v string) []int {
	v = strings.TrimSpace(v)
	if v == "" {
		v = "0.0.0"
	}
	parts := strings.Split(v, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		n, err := strconv.Atoi(p)
		if err != nil {
			n = 0
		}
		out = append(out, n)
	}
	return out
}

func invalidBroadcasterVersion(version string, minVersion, maxVersion string) bool {
	if version == "" {
		version = "0.0.0"
	}
	return versionCompare(version, minVersion) < 0 || versionCompare(version, maxVersion) > 0
}

func cachedFeeExpired(feeExpiration int64, nowMS int64) bool {
	return feeExpiration < nowMS+feeExpirationMinimumMS
}

func shortenAddress(address string) string {
	if len(address) < 13 {
		return address
	}
	return address[:8] + "..." + address[len(address)-4:]
}
