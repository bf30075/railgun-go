//go:build !rapidsnark

package sdk

import (
	"strings"
	"testing"
)

func TestNewRapidsnarkProverRequiresBuildTag(t *testing.T) {
	_, err := NewRapidsnarkProver(ProofConfig{LocalArtifactManifest: writeSDKLocalArtifactManifest(t)}, nil)
	if err == nil || !strings.Contains(err.Error(), "rapidsnark build tag") {
		t.Fatalf("expected build tag error, got %v", err)
	}
}
