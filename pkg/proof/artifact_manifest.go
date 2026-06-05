package proof

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
)

type LocalArtifactManifest struct {
	BaseDir string                     `json:"baseDir,omitempty"`
	Railgun map[string]ArtifactPathSet `json:"railgun,omitempty"`
	POI     map[string]ArtifactPathSet `json:"poi,omitempty"`
}

type RemoteArtifactManifest struct {
	CacheDir string                       `json:"cacheDir,omitempty"`
	Railgun  map[string]ArtifactSourceSet `json:"railgun,omitempty"`
	POI      map[string]ArtifactSourceSet `json:"poi,omitempty"`
}

func ParseLocalArtifactManifest(data []byte) (LocalArtifactGetter, error) {
	var manifest LocalArtifactManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return LocalArtifactGetter{}, err
	}
	return LocalArtifactGetter{
		BaseDir: manifest.BaseDir,
		Railgun: manifest.Railgun,
		POI:     manifest.POI,
	}, nil
}

func LoadLocalArtifactManifest(path string) (LocalArtifactGetter, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return LocalArtifactGetter{}, err
	}
	getter, err := ParseLocalArtifactManifest(data)
	if err != nil {
		return LocalArtifactGetter{}, err
	}
	getter.BaseDir = manifestRelativeDir(path, getter.BaseDir)
	return getter, nil
}

func ParseRemoteArtifactManifest(data []byte, httpClient *http.Client) (RemoteArtifactGetter, error) {
	var manifest RemoteArtifactManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return RemoteArtifactGetter{}, err
	}
	return RemoteArtifactGetter{
		CacheDir:   manifest.CacheDir,
		HTTPClient: httpClient,
		Railgun:    manifest.Railgun,
		POI:        manifest.POI,
	}, nil
}

func LoadRemoteArtifactManifest(path string, httpClient *http.Client) (RemoteArtifactGetter, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RemoteArtifactGetter{}, err
	}
	getter, err := ParseRemoteArtifactManifest(data, httpClient)
	if err != nil {
		return RemoteArtifactGetter{}, err
	}
	getter.CacheDir = manifestRelativeDir(path, getter.CacheDir)
	return getter, nil
}

func manifestRelativeDir(manifestPath string, value string) string {
	if filepath.IsAbs(value) {
		return value
	}
	base := filepath.Dir(manifestPath)
	if value == "" {
		return base
	}
	return filepath.Join(base, value)
}
