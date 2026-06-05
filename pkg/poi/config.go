package poi

import (
	"encoding/json"
	"os"

	railchain "github.com/bf30075/railgun-go/pkg/chain"
)

type LaunchBlockConfig struct {
	Chain       railchain.Chain `json:"chain"`
	BlockNumber uint64          `json:"blockNumber"`
}

type ManagerConfig struct {
	Lists        []List              `json:"lists,omitempty"`
	LaunchBlocks []LaunchBlockConfig `json:"launchBlocks,omitempty"`
}

func ParseManagerConfig(data []byte, node NodeInterface) (*Manager, error) {
	var config ManagerConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return NewManagerFromConfig(config, node), nil
}

func LoadManagerConfig(path string, node NodeInterface) (*Manager, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseManagerConfig(data, node)
}

func NewManagerFromConfig(config ManagerConfig, node NodeInterface) *Manager {
	manager := NewManager(config.Lists, node)
	manager.SetLaunchBlocks(config.LaunchBlocks)
	return manager
}

func (manager *Manager) SetLaunchBlocks(launchBlocks []LaunchBlockConfig) {
	for _, launchBlock := range launchBlocks {
		manager.SetLaunchBlock(launchBlock.Chain, launchBlock.BlockNumber)
	}
}
