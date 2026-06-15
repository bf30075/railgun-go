package proof

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

type ArtifactFileSource struct {
	Path   string `json:"path,omitempty"`
	URL    string `json:"url,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

type ArtifactSourceSet struct {
	WASM ArtifactFileSource `json:"wasm,omitempty"`
	ZKey ArtifactFileSource `json:"zkey,omitempty"`
	DAT  ArtifactFileSource `json:"dat,omitempty"`
	VKey ArtifactFileSource `json:"vkey,omitempty"`
}

type RemoteArtifactGetter struct {
	CacheDir   string
	HTTPClient *http.Client
	Railgun    map[string]ArtifactSourceSet
	POI        map[string]ArtifactSourceSet
}

func (getter RemoteArtifactGetter) AssertArtifactExists(nullifiers int, commitments int) error {
	key := RailgunArtifactKey(nullifiers, commitments)
	if _, ok := getter.Railgun[key]; !ok {
		return fmt.Errorf("missing railgun artifact %s", key)
	}
	return nil
}

func (getter RemoteArtifactGetter) GetArtifacts(ctx context.Context, publicInputs PublicInputsRailgun) (Artifact, error) {
	key := RailgunArtifactKey(len(publicInputs.Nullifiers), len(publicInputs.CommitmentsOut))
	sources, ok := getter.Railgun[key]
	if !ok {
		return Artifact{}, fmt.Errorf("missing railgun artifact %s", key)
	}
	return getter.readArtifact(ctx, sources)
}

func (getter RemoteArtifactGetter) GetArtifactsPOI(ctx context.Context, maxInputs int, maxOutputs int) (Artifact, error) {
	key := POIArtifactKey(maxInputs, maxOutputs)
	sources, ok := getter.POI[key]
	if !ok {
		return Artifact{}, fmt.Errorf("missing poi artifact %s", key)
	}
	return getter.readArtifact(ctx, sources)
}

func (getter RemoteArtifactGetter) readArtifact(ctx context.Context, sources ArtifactSourceSet) (Artifact, error) {
	wasm, err := getter.readOptional(ctx, sources.WASM)
	if err != nil {
		return Artifact{}, fmt.Errorf("wasm artifact: %w", err)
	}
	zkey, err := getter.readOptional(ctx, sources.ZKey)
	if err != nil {
		return Artifact{}, fmt.Errorf("zkey artifact: %w", err)
	}
	dat, err := getter.readOptional(ctx, sources.DAT)
	if err != nil {
		return Artifact{}, fmt.Errorf("dat artifact: %w", err)
	}
	vkey, err := getter.readOptional(ctx, sources.VKey)
	if err != nil {
		return Artifact{}, fmt.Errorf("vkey artifact: %w", err)
	}
	artifact := Artifact{
		WASM: wasm,
		ZKey: zkey,
		DAT:  dat,
	}
	if vkey != nil {
		artifact.VKey = vkey
	}
	return artifact, nil
}

func (getter RemoteArtifactGetter) readOptional(ctx context.Context, source ArtifactFileSource) ([]byte, error) {
	if source.Path == "" && source.URL == "" {
		return nil, nil
	}
	path := getter.resolvePath(source)
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			if err := assertArtifactSHA256(data, source.SHA256); err == nil {
				return data, nil
			} else if source.URL == "" {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) || source.URL == "" {
			return nil, err
		}
	}
	if source.URL == "" {
		return nil, fmt.Errorf("missing local artifact %s", path)
	}

	data, err := getter.download(ctx, source.URL)
	if err != nil {
		return nil, err
	}
	if err := assertArtifactSHA256(data, source.SHA256); err != nil {
		return nil, err
	}
	if path != "" {
		if err := writeArtifactCache(path, data); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func (getter RemoteArtifactGetter) download(ctx context.Context, artifactURL string) ([]byte, error) {
	client := getter.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifactURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("download %s: HTTP %d", artifactURL, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func (getter RemoteArtifactGetter) resolvePath(source ArtifactFileSource) string {
	if source.Path != "" {
		if filepath.IsAbs(source.Path) || getter.CacheDir == "" {
			return source.Path
		}
		return filepath.Join(getter.CacheDir, source.Path)
	}
	if getter.CacheDir == "" || source.URL == "" {
		return ""
	}
	return filepath.Join(getter.CacheDir, artifactCacheFilename(source.URL))
}

func assertArtifactSHA256(data []byte, expected string) error {
	if expected == "" {
		return nil
	}
	hash := sha256.Sum256(data)
	actual := hex.EncodeToString(hash[:])
	if actual != expected {
		return fmt.Errorf("sha256 mismatch: expected %s got %s", expected, actual)
	}
	return nil
}

func writeArtifactCache(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".artifact-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func artifactCacheFilename(rawURL string) string {
	hash := sha256.Sum256([]byte(rawURL))
	name := "artifact.bin"
	parsed, err := url.Parse(rawURL)
	if err == nil {
		base := filepath.Base(parsed.Path)
		if base != "." && base != "/" && base != "" {
			name = base
		}
	}
	return hex.EncodeToString(hash[:8]) + "-" + name
}
