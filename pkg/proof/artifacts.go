package proof

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

type ArtifactPathSet struct {
	WASM string `json:"wasm,omitempty"`
	ZKey string `json:"zkey,omitempty"`
	DAT  string `json:"dat,omitempty"`
	VKey string `json:"vkey,omitempty"`
}

type LocalArtifactGetter struct {
	BaseDir string
	Railgun map[string]ArtifactPathSet
	POI     map[string]ArtifactPathSet
}

func RailgunArtifactKey(nullifiers int, commitments int) string {
	return fmt.Sprintf("railgun_%dx%d", nullifiers, commitments)
}

func POIArtifactKey(maxInputs int, maxOutputs int) string {
	return fmt.Sprintf("poi_%dx%d", maxInputs, maxOutputs)
}

func (getter LocalArtifactGetter) AssertArtifactExists(nullifiers int, commitments int) error {
	key := RailgunArtifactKey(nullifiers, commitments)
	if _, ok := getter.Railgun[key]; !ok {
		return fmt.Errorf("missing railgun artifact %s", key)
	}
	return nil
}

func (getter LocalArtifactGetter) GetArtifacts(ctx context.Context, publicInputs PublicInputsRailgun) (Artifact, error) {
	key := RailgunArtifactKey(len(publicInputs.Nullifiers), len(publicInputs.CommitmentsOut))
	paths, ok := getter.Railgun[key]
	if !ok {
		return Artifact{}, fmt.Errorf("missing railgun artifact %s", key)
	}
	return getter.readArtifact(ctx, paths)
}

func (getter LocalArtifactGetter) GetArtifactsPOI(ctx context.Context, maxInputs int, maxOutputs int) (Artifact, error) {
	key := POIArtifactKey(maxInputs, maxOutputs)
	paths, ok := getter.POI[key]
	if !ok {
		return Artifact{}, fmt.Errorf("missing poi artifact %s", key)
	}
	return getter.readArtifact(ctx, paths)
}

func (getter LocalArtifactGetter) readArtifact(ctx context.Context, paths ArtifactPathSet) (Artifact, error) {
	if err := ctx.Err(); err != nil {
		return Artifact{}, err
	}
	wasm, err := getter.readOptional(paths.WASM)
	if err != nil {
		return Artifact{}, fmt.Errorf("wasm artifact: %w", err)
	}
	zkey, err := getter.readOptional(paths.ZKey)
	if err != nil {
		return Artifact{}, fmt.Errorf("zkey artifact: %w", err)
	}
	dat, err := getter.readOptional(paths.DAT)
	if err != nil {
		return Artifact{}, fmt.Errorf("dat artifact: %w", err)
	}
	vkey, err := getter.readOptional(paths.VKey)
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

func (getter LocalArtifactGetter) readOptional(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	return os.ReadFile(getter.resolvePath(path))
}

func (getter LocalArtifactGetter) resolvePath(path string) string {
	if filepath.IsAbs(path) || getter.BaseDir == "" {
		return path
	}
	return filepath.Join(getter.BaseDir, path)
}
