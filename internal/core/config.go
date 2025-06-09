package core

import (
	"encoding/json"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ShodanAPIKey string            `json:"shodan_api_key" yaml:"shodan_api_key"`
	CensysID     string            `json:"censys_id" yaml:"censys_id"`
	CensysSecret string            `json:"censys_secret" yaml:"censys_secret"`
	Modules      []string          `json:"modules" yaml:"modules"`
	Constants    map[string]string `json:"constants" yaml:"constants"`
}

func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var cfg Config
	if len(path) > 5 && path[len(path)-5:] == ".yaml" {
		err = yaml.NewDecoder(f).Decode(&cfg)
	} else {
		err = json.NewDecoder(f).Decode(&cfg)
	}
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
