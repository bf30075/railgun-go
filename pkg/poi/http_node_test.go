package poi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
	"github.com/bf30075/railgun-go/pkg/merkletree"
	railproof "github.com/bf30075/railgun-go/pkg/proof"
)

func TestHTTPNodeImplementsNodeInterface(t *testing.T) {
	ctx := context.Background()
	chain := railchain.Chain{Type: 0, ID: 1}
	pathsSeen := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("x-api-key") != "secret" {
			t.Fatalf("expected x-api-key header")
		}
		pathsSeen[r.URL.Path] = true
		switch r.URL.Path {
		case "/is-required":
			var request struct {
				Chain railchain.Chain `json:"chain"`
			}
			decodeRequest(t, r, &request)
			if request.Chain != chain {
				t.Fatalf("unexpected is-required chain %+v", request.Chain)
			}
			writeJSON(t, w, map[string]bool{"required": true})
		case "/get-pois-per-list":
			var request GetPOIsPerListRequest
			raw := decodeRequest(t, r, &request)
			assertHasJSONKey(t, raw, "txidVersion")
			assertHasJSONKey(t, raw, "blindedCommitmentDatas")
			if request.TXIDVersion != "V2_PoseidonMerkle" || len(request.ListKeys) != 2 {
				t.Fatalf("unexpected POIs request %+v", request)
			}
			writeJSON(t, w, map[string]map[string]POIsPerList{
				"poisPerList": {
					"0xabc": {managerMockList: TXOPOIListStatusValid},
				},
			})
		case "/get-poi-merkle-proofs":
			var request GetPOIMerkleProofsRequest
			decodeRequest(t, r, &request)
			if request.ListKey != managerMockList || len(request.BlindedCommitments) != 1 {
				t.Fatalf("unexpected merkle proof request %+v", request)
			}
			writeJSON(t, w, map[string][]merkletree.MerkleProof{
				"merkleProofs": {{Leaf: "0xabc", Indices: "0x00", Elements: []string{"0x00"}, Root: "0xdef"}},
			})
		case "/validate-poi-merkle-roots":
			var request ValidatePOIMerkleRootsRequest
			raw := decodeRequest(t, r, &request)
			assertHasJSONKey(t, raw, "poiMerkleroots")
			if request.ListKey != managerMockList || len(request.POIMerkleRoots) != 1 {
				t.Fatalf("unexpected validate request %+v", request)
			}
			writeJSON(t, w, map[string]bool{"valid": true})
		case "/submit-poi":
			var request SubmitPOIRequest
			raw := decodeRequest(t, r, &request)
			assertHasJSONKey(t, raw, "txidMerkleroot")
			assertHasJSONKey(t, raw, "txidMerklerootIndex")
			if request.TxidMerkleRoot != "0xroot" || request.TxidMerkleRootIndex != 7 {
				t.Fatalf("unexpected submit POI request %+v", request)
			}
			w.WriteHeader(http.StatusNoContent)
		case "/submit-legacy-transact-proofs":
			var request SubmitLegacyTransactProofsRequest
			raw := decodeRequest(t, r, &request)
			assertHasJSONKey(t, raw, "legacyTransactProofDatas")
			if len(request.LegacyTransactProofDatas) != 1 || request.LegacyTransactProofDatas[0].TXIDIndex != "1" {
				t.Fatalf("unexpected legacy submit request %+v", request)
			}
			writeJSON(t, w, map[string]bool{"success": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	node, err := NewHTTPNode(server.URL, HTTPNodeOptions{
		Headers:      map[string]string{"x-api-key": "secret"},
		ActiveChains: []railchain.Chain{chain},
	})
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager([]List{
		{Key: managerMockList, Type: ListTypeGather, Name: "mock", Description: "mock"},
		{Key: managerActiveList, Type: ListTypeActive, Name: "active", Description: "active"},
	}, node)

	if !manager.IsActiveForChain(chain) {
		t.Fatal("expected configured chain to be active")
	}
	if manager.IsActiveForChain(railchain.Chain{Type: 0, ID: 5}) {
		t.Fatal("expected unconfigured chain to be inactive")
	}
	required, err := manager.IsRequiredForChain(ctx, chain)
	if err != nil {
		t.Fatal(err)
	}
	if !required {
		t.Fatal("expected POI required")
	}
	pois, err := manager.RetrievePOIsForBlindedCommitments(ctx, "V2_PoseidonMerkle", chain, []BlindedCommitmentData{
		{BlindedCommitment: "0xabc", Type: BlindedCommitmentTypeTransact},
	})
	if err != nil {
		t.Fatal(err)
	}
	if pois["0xabc"][managerMockList] != TXOPOIListStatusValid {
		t.Fatalf("unexpected POIs %+v", pois)
	}
	proofs, err := manager.GetPOIMerkleProofs(ctx, "V2_PoseidonMerkle", chain, managerMockList, []string{"0xabc"})
	if err != nil {
		t.Fatal(err)
	}
	if len(proofs) != 1 || proofs[0].Leaf != "0xabc" {
		t.Fatalf("unexpected proofs %+v", proofs)
	}
	ok, err := manager.ValidatePOIMerkleRoots(ctx, "V2_PoseidonMerkle", chain, managerMockList, []string{"0xdef"})
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected valid roots")
	}
	if err := manager.SubmitPOI(ctx, SubmitPOIRequest{
		TXIDVersion:              "V2_PoseidonMerkle",
		Chain:                    chain,
		ListKey:                  managerMockList,
		SnarkProof:               railproof.Proof{},
		POIMerkleRoots:           []string{"0xdef"},
		TxidMerkleRoot:           "0xroot",
		TxidMerkleRootIndex:      7,
		BlindedCommitmentsOut:    []string{"0xout"},
		RailgunTxidIfHasUnshield: "0x00",
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.SubmitLegacyTransactProofs(ctx, SubmitLegacyTransactProofsRequest{
		TXIDVersion: "V2_PoseidonMerkle",
		Chain:       chain,
		ListKeys:    []string{managerMockList},
		LegacyTransactProofDatas: []LegacyTransactProofData{
			{TXIDIndex: "1", NPK: "0xnpk", Value: "1", TokenHash: "0xtoken", BlindedCommitment: "0xabc"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/is-required",
		"/get-pois-per-list",
		"/get-poi-merkle-proofs",
		"/validate-poi-merkle-roots",
		"/submit-poi",
		"/submit-legacy-transact-proofs",
	} {
		if !pathsSeen[path] {
			t.Fatalf("expected path %s to be called", path)
		}
	}
}

func TestHTTPNodeErrorResponses(t *testing.T) {
	ctx := context.Background()
	chain := railchain.Chain{Type: 0, ID: 1}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/is-required":
			http.Error(w, "offline", http.StatusBadGateway)
		case "/validate-poi-merkle-roots":
			writeJSON(t, w, map[string]any{"success": false, "message": "bad roots"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	node, err := NewHTTPNode(server.URL, HTTPNodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := node.IsRequired(ctx, chain); err == nil || !strings.Contains(err.Error(), "poi node status 502") {
		t.Fatalf("expected status error, got %v", err)
	}
	_, err = node.ValidatePOIMerkleRoots(ctx, ValidatePOIMerkleRootsRequest{Chain: chain})
	if err == nil || err.Error() != "poi node error: bad roots" {
		t.Fatalf("unexpected error %v", err)
	}
}

func decodeRequest(t *testing.T, request *http.Request, out any) map[string]json.RawMessage {
	t.Helper()
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(request.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertHasJSONKey(t *testing.T, raw map[string]json.RawMessage, key string) {
	t.Helper()
	if _, ok := raw[key]; !ok {
		t.Fatalf("expected request JSON key %s in %+v", key, raw)
	}
}

func writeJSON(t *testing.T, response http.ResponseWriter, value any) {
	t.Helper()
	response.Header().Set("content-type", "application/json")
	if err := json.NewEncoder(response).Encode(value); err != nil {
		t.Fatal(err)
	}
}
