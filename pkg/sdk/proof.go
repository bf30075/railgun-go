package sdk

import (
	"fmt"
	"net/http"

	railproof "github.com/bf30075/railgun-go/pkg/proof"
)

// ArtifactSourceType 选择 proof artifact 的加载来源。
type ArtifactSourceType string

const (
	// ArtifactSourceLocal 从本地 manifest 加载 artifact。
	ArtifactSourceLocal ArtifactSourceType = "local"
	// ArtifactSourceRemote 从远程 manifest 加载 artifact。
	ArtifactSourceRemote ArtifactSourceType = "remote"
)

// ProofConfig 配置 proof artifact 加载和可选 native prover。
type ProofConfig struct {
	// ArtifactSource 显式选择本地或远程 artifact 加载。
	ArtifactSource ArtifactSourceType `json:"artifactSource,omitempty"`
	// LocalArtifactManifest 指向本地 proof artifact manifest。
	LocalArtifactManifest string `json:"localArtifactManifest,omitempty"`
	// RemoteArtifactManifest 指向远程 proof artifact manifest。
	RemoteArtifactManifest string `json:"remoteArtifactManifest,omitempty"`
	// RapidsnarkProverBinary 覆盖 rapidsnark prover 可执行文件路径。
	RapidsnarkProverBinary string `json:"rapidsnarkProverBinary,omitempty"`
}

// ArtifactGetter 构造已配置的 proof artifact getter。
func (config ProofConfig) ArtifactGetter(httpClient *http.Client) (railproof.ArtifactGetter, error) {
	source, err := config.resolveArtifactSource()
	if err != nil {
		return nil, err
	}
	switch source {
	case ArtifactSourceLocal:
		if config.LocalArtifactManifest == "" {
			return nil, fmt.Errorf("localArtifactManifest is required")
		}
		return railproof.LoadLocalArtifactManifest(config.LocalArtifactManifest)
	case ArtifactSourceRemote:
		if config.RemoteArtifactManifest == "" {
			return nil, fmt.Errorf("remoteArtifactManifest is required")
		}
		return railproof.LoadRemoteArtifactManifest(config.RemoteArtifactManifest, httpClient)
	default:
		return nil, fmt.Errorf("unsupported artifact source %s", source)
	}
}

// NewProver 使用 config、backend 和 HTTP client 创建 proof prover。
func NewProver(config ProofConfig, backend railproof.Backend, httpClient *http.Client) (*railproof.Prover, error) {
	getter, err := config.ArtifactGetter(httpClient)
	if err != nil {
		return nil, err
	}
	return railproof.NewProver(getter, backend), nil
}

func (config ProofConfig) resolveArtifactSource() (ArtifactSourceType, error) {
	if config.ArtifactSource != "" {
		return config.ArtifactSource, nil
	}
	hasLocal := config.LocalArtifactManifest != ""
	hasRemote := config.RemoteArtifactManifest != ""
	switch {
	case hasLocal && hasRemote:
		return "", fmt.Errorf("only one artifact manifest source may be configured")
	case hasLocal:
		return ArtifactSourceLocal, nil
	case hasRemote:
		return ArtifactSourceRemote, nil
	default:
		return "", fmt.Errorf("artifact manifest is required")
	}
}
