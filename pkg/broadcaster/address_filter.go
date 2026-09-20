package broadcaster

import "strings"

// AddressFilter mirrors packages/common/src/filters/address-filter.ts.
type AddressFilter struct {
	allowlist map[string]struct{}
	blocklist map[string]struct{}
}

func NewAddressFilter() *AddressFilter {
	return &AddressFilter{}
}

func (f *AddressFilter) SetAllowlist(addresses []string) {
	f.allowlist = toLowerSet(addresses)
}

func (f *AddressFilter) SetBlocklist(addresses []string) {
	f.blocklist = toLowerSet(addresses)
}

func (f *AddressFilter) Filter(addresses []string) []string {
	out := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		lower := strings.ToLower(addr)
		if len(f.blocklist) > 0 {
			if _, blocked := f.blocklist[lower]; blocked {
				continue
			}
		}
		if len(f.allowlist) > 0 {
			if _, allowed := f.allowlist[lower]; !allowed {
				continue
			}
		}
		out = append(out, addr)
	}
	return out
}

func toLowerSet(addresses []string) map[string]struct{} {
	if len(addresses) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(addresses))
	for _, addr := range addresses {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		out[strings.ToLower(addr)] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
