package proof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestLocalArtifactGetterLoadsRailgunArtifacts(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "railgun.wasm", "wasm")
	writeTestFile(t, dir, "railgun.zkey", "zkey")
	writeTestFile(t, dir, "railgun.vkey.json", `{"protocol":"groth16"}`)

	getter := LocalArtifactGetter{
		BaseDir: dir,
		Railgun: map[string]ArtifactPathSet{
			RailgunArtifactKey(1, 2): {
				WASM: "railgun.wasm",
				ZKey: "railgun.zkey",
				VKey: "railgun.vkey.json",
			},
		},
	}
	if err := getter.AssertArtifactExists(1, 2); err != nil {
		t.Fatal(err)
	}
	artifact, err := getter.GetArtifacts(context.Background(), PublicInputsRailgun{
		Nullifiers:     []*big.Int{big.NewInt(1)},
		CommitmentsOut: []*big.Int{big.NewInt(2), big.NewInt(3)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(artifact.WASM) != "wasm" {
		t.Fatalf("expected wasm artifact, got %q", artifact.WASM)
	}
	if string(artifact.ZKey) != "zkey" {
		t.Fatalf("expected zkey artifact, got %q", artifact.ZKey)
	}
	if string(artifact.VKey.([]byte)) != `{"protocol":"groth16"}` {
		t.Fatalf("expected vkey artifact, got %q", artifact.VKey)
	}
}

func TestLocalArtifactGetterLoadsPOIArtifacts(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "poi.wasm", "poi-wasm")
	writeTestFile(t, dir, "poi.zkey", "poi-zkey")

	getter := LocalArtifactGetter{
		BaseDir: dir,
		POI: map[string]ArtifactPathSet{
			POIArtifactKey(3, 3): {
				WASM: "poi.wasm",
				ZKey: "poi.zkey",
			},
		},
	}
	artifact, err := getter.GetArtifactsPOI(context.Background(), 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(artifact.WASM) != "poi-wasm" {
		t.Fatalf("expected poi wasm artifact, got %q", artifact.WASM)
	}
	if string(artifact.ZKey) != "poi-zkey" {
		t.Fatalf("expected poi zkey artifact, got %q", artifact.ZKey)
	}
}

func TestLocalArtifactGetterRejectsMissingArtifact(t *testing.T) {
	getter := LocalArtifactGetter{}
	if err := getter.AssertArtifactExists(1, 2); err == nil {
		t.Fatal("expected missing railgun artifact")
	}
	if _, err := getter.GetArtifactsPOI(context.Background(), 3, 3); err == nil {
		t.Fatal("expected missing poi artifact")
	}
}

func TestLoadLocalArtifactManifestResolvesRelativeBaseDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "artifacts"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(dir, "artifacts"), "poi.wasm", "manifest-poi-wasm")
	writeTestFile(t, filepath.Join(dir, "artifacts"), "poi.zkey", "manifest-poi-zkey")
	manifestPath := filepath.Join(dir, "artifacts.json")
	manifest := `{
		"baseDir": "artifacts",
		"poi": {
			"poi_3x3": {
				"wasm": "poi.wasm",
				"zkey": "poi.zkey"
			}
		}
	}`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	getter, err := LoadLocalArtifactManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := getter.GetArtifactsPOI(context.Background(), 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(artifact.WASM) != "manifest-poi-wasm" || string(artifact.ZKey) != "manifest-poi-zkey" {
		t.Fatalf("unexpected manifest artifacts wasm=%q zkey=%q", artifact.WASM, artifact.ZKey)
	}
}

func TestRemoteArtifactGetterDownloadsCachesAndLoadsArtifacts(t *testing.T) {
	dir := t.TempDir()
	contents := map[string][]byte{
		"/wasm": []byte("remote-wasm"),
		"/zkey": []byte("remote-zkey"),
		"/vkey": []byte(`{"protocol":"groth16"}`),
	}
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := contents[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		hits.Add(1)
		_, _ = w.Write(data)
	}))
	defer server.Close()

	getter := RemoteArtifactGetter{
		CacheDir: dir,
		Railgun: map[string]ArtifactSourceSet{
			RailgunArtifactKey(1, 2): {
				WASM: ArtifactFileSource{
					URL:    server.URL + "/wasm",
					Path:   "railgun/1x2.wasm",
					SHA256: testSHA256(contents["/wasm"]),
				},
				ZKey: ArtifactFileSource{
					URL:    server.URL + "/zkey",
					Path:   "railgun/1x2.zkey",
					SHA256: testSHA256(contents["/zkey"]),
				},
				VKey: ArtifactFileSource{
					URL:    server.URL + "/vkey",
					Path:   "railgun/1x2.vkey.json",
					SHA256: testSHA256(contents["/vkey"]),
				},
			},
		},
	}

	artifact, err := getter.GetArtifacts(context.Background(), PublicInputsRailgun{
		Nullifiers:     []*big.Int{big.NewInt(1)},
		CommitmentsOut: []*big.Int{big.NewInt(2), big.NewInt(3)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(artifact.WASM) != "remote-wasm" {
		t.Fatalf("expected remote wasm artifact, got %q", artifact.WASM)
	}
	if string(artifact.ZKey) != "remote-zkey" {
		t.Fatalf("expected remote zkey artifact, got %q", artifact.ZKey)
	}
	if string(artifact.VKey.([]byte)) != `{"protocol":"groth16"}` {
		t.Fatalf("expected remote vkey artifact, got %q", artifact.VKey)
	}
	if hits.Load() != 3 {
		t.Fatalf("expected 3 artifact downloads, got %d", hits.Load())
	}

	artifact, err = getter.GetArtifacts(context.Background(), PublicInputsRailgun{
		Nullifiers:     []*big.Int{big.NewInt(1)},
		CommitmentsOut: []*big.Int{big.NewInt(2), big.NewInt(3)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(artifact.WASM) != "remote-wasm" {
		t.Fatalf("expected cached wasm artifact, got %q", artifact.WASM)
	}
	if hits.Load() != 3 {
		t.Fatalf("expected second load to use cache, got %d downloads", hits.Load())
	}
	if _, err := os.Stat(filepath.Join(dir, "railgun/1x2.wasm")); err != nil {
		t.Fatal(err)
	}
}

func TestLoadRemoteArtifactManifestResolvesRelativeCacheDir(t *testing.T) {
	dir := t.TempDir()
	contents := map[string][]byte{
		"/wasm": []byte("manifest-remote-wasm"),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, ok := contents[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(data)
	}))
	defer server.Close()
	manifestPath := filepath.Join(dir, "remote-artifacts.json")
	manifest := `{
		"cacheDir": "cache",
		"poi": {
			"poi_3x3": {
				"wasm": {
					"url": "` + server.URL + `/wasm",
					"path": "poi/3x3.wasm",
					"sha256": "` + testSHA256(contents["/wasm"]) + `"
				}
			}
		}
	}`
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	getter, err := LoadRemoteArtifactManifest(manifestPath, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := getter.GetArtifactsPOI(context.Background(), 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	if string(artifact.WASM) != "manifest-remote-wasm" {
		t.Fatalf("unexpected manifest remote wasm %q", artifact.WASM)
	}
	if _, err := os.Stat(filepath.Join(dir, "cache", "poi", "3x3.wasm")); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteArtifactGetterRejectsSHA256Mismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("actual"))
	}))
	defer server.Close()

	getter := RemoteArtifactGetter{
		CacheDir: t.TempDir(),
		POI: map[string]ArtifactSourceSet{
			POIArtifactKey(3, 3): {
				WASM: ArtifactFileSource{
					URL:    server.URL + "/wasm",
					Path:   "poi/3x3.wasm",
					SHA256: testSHA256([]byte("expected")),
				},
			},
		},
	}
	_, err := getter.GetArtifactsPOI(context.Background(), 3, 3)
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected sha256 mismatch, got %v", err)
	}
}

func writeTestFile(t *testing.T, dir string, name string, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func testSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
