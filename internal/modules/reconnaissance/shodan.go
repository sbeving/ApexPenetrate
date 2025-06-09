// internal/modules/reconnaissance/shodan.go
package reconnaissance

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type ShodanResult struct {
	IPStr     string   `json:"ip_str"`
	Hostnames []string `json:"hostnames"`
	Ports     []int    `json:"ports"`
	Org       string   `json:"org"`
	ISP       string   `json:"isp"`
	OS        string   `json:"os"`
	Data      []struct {
		Port   int    `json:"port"`
		Banner string `json:"data"`
	} `json:"data"`
}

func ShodanHostLookup(apiKey, target string) (*ShodanResult, error) {
	url := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", target, apiKey)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Shodan API error: %s", resp.Status)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	var result ShodanResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
