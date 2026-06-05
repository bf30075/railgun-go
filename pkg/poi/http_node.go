package poi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	"github.com/bf30075/railgun-go/pkg/merkletree"
)

type HTTPNodePaths struct {
	IsRequired                 string
	GetPOIsPerList             string
	GetPOIMerkleProofs         string
	ValidatePOIMerkleRoots     string
	SubmitPOI                  string
	SubmitLegacyTransactProofs string
}

type HTTPNodeOptions struct {
	Client       *http.Client
	Paths        HTTPNodePaths
	Headers      map[string]string
	ActiveChains []railchain.Chain
}

type HTTPNode struct {
	BaseURL      string
	Client       *http.Client
	Paths        HTTPNodePaths
	Headers      map[string]string
	ActiveChains []railchain.Chain
}

func NewHTTPNode(baseURL string, options HTTPNodeOptions) (*HTTPNode, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		return nil, fmt.Errorf("poi node base URL is required")
	}
	return &HTTPNode{
		BaseURL:      baseURL,
		Client:       options.Client,
		Paths:        normalizeHTTPNodePaths(options.Paths),
		Headers:      cloneStringMap(options.Headers),
		ActiveChains: append([]railchain.Chain(nil), options.ActiveChains...),
	}, nil
}

func (node *HTTPNode) IsActive(chain railchain.Chain) bool {
	if node == nil || node.BaseURL == "" {
		return false
	}
	if len(node.ActiveChains) == 0 {
		return true
	}
	for _, activeChain := range node.ActiveChains {
		if activeChain == chain {
			return true
		}
	}
	return false
}

func (node *HTTPNode) IsRequired(ctx context.Context, chain railchain.Chain) (bool, error) {
	raw, err := node.post(ctx, node.paths().IsRequired, map[string]railchain.Chain{"chain": chain})
	if err != nil {
		return false, err
	}
	return decodeBoolResponse(raw, "required", "isRequired", "result")
}

func (node *HTTPNode) GetPOIsPerList(ctx context.Context, request GetPOIsPerListRequest) (map[string]POIsPerList, error) {
	raw, err := node.post(ctx, node.paths().GetPOIsPerList, request)
	if err != nil {
		return nil, err
	}
	return decodePOIsPerListResponse(raw)
}

func (node *HTTPNode) GetPOIMerkleProofs(ctx context.Context, request GetPOIMerkleProofsRequest) ([]merkletree.MerkleProof, error) {
	raw, err := node.post(ctx, node.paths().GetPOIMerkleProofs, request)
	if err != nil {
		return nil, err
	}
	return decodeMerkleProofsResponse(raw)
}

func (node *HTTPNode) ValidatePOIMerkleRoots(ctx context.Context, request ValidatePOIMerkleRootsRequest) (bool, error) {
	raw, err := node.post(ctx, node.paths().ValidatePOIMerkleRoots, request)
	if err != nil {
		return false, err
	}
	return decodeBoolResponse(raw, "valid", "isValid", "result")
}

func (node *HTTPNode) SubmitPOI(ctx context.Context, request SubmitPOIRequest) error {
	_, err := node.post(ctx, node.paths().SubmitPOI, request)
	return err
}

func (node *HTTPNode) SubmitLegacyTransactProofs(ctx context.Context, request SubmitLegacyTransactProofsRequest) error {
	_, err := node.post(ctx, node.paths().SubmitLegacyTransactProofs, request)
	return err
}

func (node *HTTPNode) post(ctx context.Context, path string, payload any) (json.RawMessage, error) {
	if node == nil || node.BaseURL == "" {
		return nil, fmt.Errorf("poi node base URL is required")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, node.endpoint(path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	for key, value := range node.Headers {
		req.Header.Set(key, value)
	}

	client := node.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("poi node status %d: %s", resp.StatusCode, string(responseBody))
	}
	if len(bytes.TrimSpace(responseBody)) == 0 {
		return nil, nil
	}
	if err := responseError(responseBody); err != nil {
		return nil, err
	}
	return responseBody, nil
}

func (node *HTTPNode) endpoint(path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	return strings.TrimRight(node.BaseURL, "/") + "/" + strings.TrimLeft(path, "/")
}

func (node *HTTPNode) paths() HTTPNodePaths {
	if node == nil {
		return defaultHTTPNodePaths()
	}
	return normalizeHTTPNodePaths(node.Paths)
}

func normalizeHTTPNodePaths(paths HTTPNodePaths) HTTPNodePaths {
	defaults := defaultHTTPNodePaths()
	if paths.IsRequired == "" {
		paths.IsRequired = defaults.IsRequired
	}
	if paths.GetPOIsPerList == "" {
		paths.GetPOIsPerList = defaults.GetPOIsPerList
	}
	if paths.GetPOIMerkleProofs == "" {
		paths.GetPOIMerkleProofs = defaults.GetPOIMerkleProofs
	}
	if paths.ValidatePOIMerkleRoots == "" {
		paths.ValidatePOIMerkleRoots = defaults.ValidatePOIMerkleRoots
	}
	if paths.SubmitPOI == "" {
		paths.SubmitPOI = defaults.SubmitPOI
	}
	if paths.SubmitLegacyTransactProofs == "" {
		paths.SubmitLegacyTransactProofs = defaults.SubmitLegacyTransactProofs
	}
	return paths
}

func defaultHTTPNodePaths() HTTPNodePaths {
	return HTTPNodePaths{
		IsRequired:                 "/is-required",
		GetPOIsPerList:             "/get-pois-per-list",
		GetPOIMerkleProofs:         "/get-poi-merkle-proofs",
		ValidatePOIMerkleRoots:     "/validate-poi-merkle-roots",
		SubmitPOI:                  "/submit-poi",
		SubmitLegacyTransactProofs: "/submit-legacy-transact-proofs",
	}
}

func decodeBoolResponse(raw json.RawMessage, fields ...string) (bool, error) {
	if len(raw) == 0 {
		return false, fmt.Errorf("empty poi node boolean response")
	}
	var direct bool
	if err := json.Unmarshal(raw, &direct); err == nil {
		return direct, nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return false, err
	}
	for _, field := range fields {
		if value, ok := object[field]; ok {
			var out bool
			if err := json.Unmarshal(value, &out); err != nil {
				return false, err
			}
			return out, nil
		}
	}
	return false, fmt.Errorf("missing boolean field in poi node response")
}

func decodePOIsPerListResponse(raw json.RawMessage) (map[string]POIsPerList, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty poi node POI response")
	}
	var direct map[string]POIsPerList
	if err := json.Unmarshal(raw, &direct); err == nil && direct != nil {
		return direct, nil
	}
	var wrapped struct {
		POIsPerList map[string]POIsPerList `json:"poisPerList"`
		Result      map[string]POIsPerList `json:"result"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	if wrapped.POIsPerList != nil {
		return wrapped.POIsPerList, nil
	}
	if wrapped.Result != nil {
		return wrapped.Result, nil
	}
	return nil, fmt.Errorf("missing POIs in poi node response")
}

func decodeMerkleProofsResponse(raw json.RawMessage) ([]merkletree.MerkleProof, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty poi node merkle proof response")
	}
	var direct []merkletree.MerkleProof
	if err := json.Unmarshal(raw, &direct); err == nil && direct != nil {
		return direct, nil
	}
	var wrapped struct {
		MerkleProofs []merkletree.MerkleProof `json:"merkleProofs"`
		Proofs       []merkletree.MerkleProof `json:"proofs"`
		Result       []merkletree.MerkleProof `json:"result"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return nil, err
	}
	if wrapped.MerkleProofs != nil {
		return wrapped.MerkleProofs, nil
	}
	if wrapped.Proofs != nil {
		return wrapped.Proofs, nil
	}
	if wrapped.Result != nil {
		return wrapped.Result, nil
	}
	return nil, fmt.Errorf("missing merkle proofs in poi node response")
}

func responseError(raw []byte) error {
	var decoded struct {
		Error   any    `json:"error"`
		Message string `json:"message"`
		Success *bool  `json:"success"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil
	}
	if decoded.Error != nil {
		switch value := decoded.Error.(type) {
		case string:
			return fmt.Errorf("poi node error: %s", value)
		default:
			return fmt.Errorf("poi node error: %v", value)
		}
	}
	if decoded.Success != nil && !*decoded.Success {
		if decoded.Message != "" {
			return fmt.Errorf("poi node error: %s", decoded.Message)
		}
		return fmt.Errorf("poi node error: success=false")
	}
	return nil
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
