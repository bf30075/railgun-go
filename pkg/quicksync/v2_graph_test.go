package quicksync

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchV2GraphFormatsEvents(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Query string `json:"query"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		var response any
		switch {
		case contains(body.Query, "query Nullifiers"):
			response = map[string]any{
				"data": map[string]any{
					"nullifiers": []any{map[string]any{
						"id":              "n1",
						"blockNumber":     "10",
						"nullifier":       "0x01",
						"transactionHash": "0x02",
						"blockTimestamp":  "100",
						"treeNumber":      0,
					}},
				},
			}
		case contains(body.Query, "query Unshields"):
			response = map[string]any{
				"data": map[string]any{
					"unshields": []any{map[string]any{
						"id":              "u1",
						"blockNumber":     "11",
						"to":              "0x0000000000000000000000000000000000000001",
						"transactionHash": "0x03",
						"fee":             "2",
						"blockTimestamp":  "101",
						"amount":          "5",
						"eventLogIndex":   "7",
						"token": map[string]any{
							"id":           "token",
							"tokenType":    "ERC20",
							"tokenSubID":   "0x00",
							"tokenAddress": "0x0000000000000000000000000000000000000002",
						},
					}},
				},
			}
		case contains(body.Query, "query Commitments"):
			response = map[string]any{
				"data": map[string]any{
					"commitments": []any{map[string]any{
						"id":                     "c1",
						"treeNumber":             0,
						"batchStartTreePosition": 0,
						"treePosition":           0,
						"blockNumber":            "12",
						"transactionHash":        "0x04",
						"blockTimestamp":         "102",
						"commitmentType":         "ShieldCommitment",
						"hash":                   "9",
						"shieldKey":              "0x05",
						"fee":                    "0",
						"encryptedBundle":        []string{"0x01", "0x02", "0x03"},
						"preimage": map[string]any{
							"id":    "p1",
							"npk":   "0x06",
							"value": "7",
							"token": map[string]any{
								"id":           "token",
								"tokenType":    "ERC20",
								"tokenSubID":   "0x00",
								"tokenAddress": "0x0000000000000000000000000000000000000002",
							},
						},
					}},
				},
			}
		default:
			t.Fatalf("unexpected query: %s", body.Query)
		}
		if err := json.NewEncoder(writer).Encode(response); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()

	events, err := FetchV2Graph(context.Background(), V2GraphOptions{
		Endpoint:   server.URL,
		StartBlock: 1,
		MaxItems:   100,
	})
	if err != nil {
		t.Fatalf("FetchV2Graph: %v", err)
	}
	if len(events.NullifierEvents) != 1 || events.NullifierEvents[0].BlockNumber != 10 {
		t.Fatalf("unexpected nullifiers: %+v", events.NullifierEvents)
	}
	if len(events.UnshieldEvents) != 1 || events.UnshieldEvents[0].Amount != "5" {
		t.Fatalf("unexpected unshields: %+v", events.UnshieldEvents)
	}
	if len(events.CommitmentEvents) != 1 || len(events.CommitmentEvents[0].Commitments) != 1 {
		t.Fatalf("unexpected commitments: %+v", events.CommitmentEvents)
	}
	commitment := events.CommitmentEvents[0].Commitments[0]
	if commitment.Hash != "0000000000000000000000000000000000000000000000000000000000000009" {
		t.Fatalf("unexpected commitment hash: %s", commitment.Hash)
	}
	if commitment.PreImage == nil || commitment.PreImage.Value != "00000000000000000000000000000007" {
		t.Fatalf("unexpected preimage: %+v", commitment.PreImage)
	}
}

func TestFetchGraphPagesUsesIDCursorWithinSameBlock(t *testing.T) {
	var requests []map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body struct {
			Variables map[string]string `json:"variables"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		requests = append(requests, body.Variables)

		items := []any{}
		switch len(requests) {
		case 1:
			for i := 0; i < defaultGraphLimit; i++ {
				items = append(items, map[string]string{
					"id":          fmt.Sprintf("id-%05d", i),
					"blockNumber": "10",
				})
			}
		case 2:
			items = append(items, map[string]string{
				"id":          "id-10000",
				"blockNumber": "10",
			})
		default:
			t.Fatalf("unexpected extra page request %+v", body.Variables)
		}
		if err := json.NewEncoder(writer).Encode(map[string]any{
			"data": map[string]any{"items": items},
		}); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}))
	defer server.Close()

	items, err := fetchGraphPages[testGraphPageItem](
		context.Background(),
		server.Client(),
		server.URL,
		`query Items($blockNumber: BigInt = 0, $id: String = "") { items { id blockNumber } }`,
		"items",
		10,
		defaultGraphLimit+1,
	)
	if err != nil {
		t.Fatalf("fetchGraphPages: %v", err)
	}
	if len(items) != defaultGraphLimit+1 {
		t.Fatalf("expected %d items, got %d", defaultGraphLimit+1, len(items))
	}
	if len(requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(requests))
	}
	if requests[0]["blockNumber"] != "10" || requests[0]["id"] != "" {
		t.Fatalf("unexpected first cursor %+v", requests[0])
	}
	if requests[1]["blockNumber"] != "10" || requests[1]["id"] != "id-09999" {
		t.Fatalf("unexpected second cursor %+v", requests[1])
	}
	if items[len(items)-1].ID != "id-10000" {
		t.Fatalf("unexpected final item %+v", items[len(items)-1])
	}
}

type testGraphPageItem struct {
	ID          string `json:"id"`
	BlockNumber string `json:"blockNumber"`
}

func (item testGraphPageItem) graphID() string          { return item.ID }
func (item testGraphPageItem) graphBlockNumber() string { return item.BlockNumber }

func contains(value string, needle string) bool {
	return strings.Contains(value, needle)
}
