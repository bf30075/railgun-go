package sdk

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	railproof "github.com/bf30075/railgun-go/pkg/proof"
)

func TestProofConfigLoadsLocalArtifactsAndBuildsProver(t *testing.T) {
	manifestPath := writeSDKLocalArtifactManifest(t)
	config := ProofConfig{LocalArtifactManifest: manifestPath}
	getter, err := config.ArtifactGetter(nil)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := getter.GetArtifactsPOI(context.Background(), 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(artifact.WASM) != "sdk-poi-wasm" || string(artifact.ZKey) != "sdk-poi-zkey" {
		t.Fatalf("unexpected artifacts wasm=%q zkey=%q", artifact.WASM, artifact.ZKey)
	}
	prover, err := NewProver(config, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prover == nil {
		t.Fatal("expected prover")
	}
}

func TestProofConfigRejectsInvalidSources(t *testing.T) {
	_, err := ProofConfig{}.ArtifactGetter(nil)
	if err == nil || !strings.Contains(err.Error(), "artifact manifest is required") {
		t.Fatalf("expected missing manifest error, got %v", err)
	}
	_, err = ProofConfig{
		LocalArtifactManifest:  "local.json",
		RemoteArtifactManifest: "remote.json",
	}.ArtifactGetter(nil)
	if err == nil || !strings.Contains(err.Error(), "only one artifact manifest") {
		t.Fatalf("expected duplicate manifest error, got %v", err)
	}
	_, err = ProofConfig{
		ArtifactSource:        ArtifactSourceRemote,
		LocalArtifactManifest: writeSDKLocalArtifactManifest(t),
	}.ArtifactGetter(nil)
	if err == nil || !strings.Contains(err.Error(), "remoteArtifactManifest") {
		t.Fatalf("expected remote manifest load error, got %v", err)
	}
}

func writeSDKLocalArtifactManifest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "poi.wasm"), []byte("sdk-poi-wasm"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "poi.zkey"), []byte("sdk-poi-zkey"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := `{
		"poi": {
			"` + railproof.POIArtifactKey(3, 3) + `": {
				"wasm": "poi.wasm",
				"zkey": "poi.zkey"
			}
		}
	}`
	path := filepath.Join(dir, "artifacts.json")
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
