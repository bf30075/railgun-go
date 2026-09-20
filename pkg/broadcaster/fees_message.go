package broadcaster

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	railaddress "github.com/bf30075/railgun-go/pkg/address"
	railchain "github.com/bf30075/railgun-go/pkg/chain"
	railcrypto "github.com/bf30075/railgun-go/pkg/crypto"
)

// HandleFeesMessage parses, verifies, and caches a fees Waku message.
func HandleFeesMessage(
	chain railchain.Chain,
	msg Message,
	expectedTopic string,
	cache *FeeCache,
	cfg *Config,
	dbg Debugger,
) {
	if dbg == nil {
		dbg = nopDebugger{}
	}
	if len(msg.Payload) == 0 {
		return
	}
	if msg.ContentTopic != "" && msg.ContentTopic != expectedTopic {
		return
	}

	var envelope FeeMessage
	if err := json.Unmarshal(msg.Payload, &envelope); err != nil {
		return
	}
	utf8Data, err := hexToUTF8(envelope.Data)
	if err != nil {
		return
	}
	var feeData FeeMessageData
	if err := json.Unmarshal([]byte(utf8Data), &feeData); err != nil {
		return
	}

	timestampMS := msg.TimestampMS
	if timestampMS == 0 {
		timestampMS = timeNowMS()
	}
	if timestampMS > 0 && timestampMS < 10_000_000_000 {
		timestampMS *= 1000
	}
	if isExpiredFeeTimestamp(timestampMS, feeData.FeeExpiration, timeNowMS()) {
		dbg.Log("Skipping fee message. Timestamp Expired.")
		return
	}
	if invalidBroadcasterVersion(feeData.Version, cfg.MinimumBroadcasterVersion, cfg.MaximumBroadcasterVersion) {
		dbg.Log("Skipping Broadcaster outside version range: " + feeData.Version)
		return
	}

	addressData, err := railaddress.Decode(feeData.RailgunAddress)
	if err != nil {
		return
	}
	viewingPub, err := railcrypto.HexToBytes(addressData.ViewingPublicKey)
	if err != nil {
		return
	}
	if !cfg.IsDev {
		ok, err := VerifyBroadcasterSignature(envelope.Signature, envelope.Data, viewingPub)
		if err != nil || !ok {
			return
		}
	}

	isTrusted := cfg.IsTrustedSigner(feeData.RailgunAddress)
	tokenFeeMap := map[string]CachedTokenFee{}
	for tokenAddress, feePerUnitGas := range feeData.Fees {
		if feePerUnitGas == "" {
			continue
		}
		if !isTrusted && cfg.HasTrustedSigner() {
			authorized, ok := cache.GetAuthorizedFee(tokenAddress)
			if !ok {
				continue
			}
			authorizedAmount, ok := newAmount(authorized.FeePerUnitGas)
			if !ok {
				continue
			}
			lower := mulPct(authorizedAmount, cfg.AuthorizedFeeVarianceLowerPct)
			upper := mulPct(authorizedAmount, cfg.AuthorizedFeeVarianceUpperPct)
			minFee := subAmount(authorizedAmount, lower)
			maxFee := addAmount(authorizedAmount, upper)
			feeAmount, ok := newAmount(feePerUnitGas)
			if !ok || cmpAmount(feeAmount, minFee) < 0 || cmpAmount(feeAmount, maxFee) > 0 {
				continue
			}
		}
		tokenFeeMap[tokenAddress] = CachedTokenFee{
			FeePerUnitGas:    feePerUnitGas,
			Expiration:       feeData.FeeExpiration,
			FeesID:           feeData.FeesID,
			AvailableWallets: feeData.AvailableWallets,
			RelayAdapt:       feeData.RelayAdapt,
			RelayAdapt7702:   feeData.RelayAdapt7702,
			Reliability:      feeData.Reliability,
		}
	}

	if isTrusted {
		cache.AddAuthorizedFees(feeData.RailgunAddress, tokenFeeMap)
	}
	if len(tokenFeeMap) == 0 {
		return
	}
	cache.AddTokenFees(
		chain,
		feeData.RailgunAddress,
		feeData.FeeExpiration,
		tokenFeeMap,
		feeData.Identifier,
		feeData.Version,
		feeData.RequiredPOIListKeys,
		cfg,
		dbg,
	)
}

func isExpiredFeeTimestamp(messageTimestampMS, feeExpiration, nowMS int64) bool {
	expirationMsec := nowMS - 45*1000
	expirationFeeMsec := nowMS + 45*1000
	timestampExpired := messageTimestampMS < expirationMsec
	feeExpired := feeExpiration < expirationFeeMsec
	return timestampExpired && feeExpired
}

func hexToUTF8(dataHex string) (string, error) {
	raw, err := railcrypto.HexToBytes(dataHex)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// VerifyBroadcasterSignature verifies an ED25519 signature over fee data.
func VerifyBroadcasterSignature(signature any, data any, viewingPublicKey []byte) (bool, error) {
	sigBytes, err := coerceBytes(signature)
	if err != nil {
		return false, err
	}
	dataBytes, err := coerceBytes(data)
	if err != nil {
		return false, err
	}
	return railcrypto.VerifyED25519(dataBytes, sigBytes, viewingPublicKey), nil
}

func coerceBytes(value any) ([]byte, error) {
	switch v := value.(type) {
	case []byte:
		return v, nil
	case string:
		trimmed := strings.TrimSpace(v)
		if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") || isHexString(trimmed) {
			decoded, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(trimmed, "0x"), "0X"))
			if err != nil {
				return nil, err
			}
			return decoded, nil
		}
		return []byte(trimmed), nil
	default:
		return nil, fmt.Errorf("unsupported signature/data type %T", value)
	}
}

func isHexString(value string) bool {
	if len(value) == 0 || len(value)%2 != 0 {
		return false
	}
	for _, c := range value {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
