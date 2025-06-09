// internal/modules/reconnaissance/censys.go
package reconnaissance

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type CensysResult struct {
	IP        string   `json:"ip"`
	Protocols []string `json:"protocols"`
	Location  struct {
		Country string `json:"country"`
		City    string `json:"city"`
	} `json:"location"`
}

func CensysHostLookup(apiID, apiSecret, target string) (*CensysResult, error) {
	url := fmt.Sprintf("https://search.censys.io/api/v2/hosts/%s", target)
	req, _ := http.NewRequest("GET", url, nil)
	req.SetBasicAuth(apiID, apiSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Censys API error: %s", resp.Status)
	}
	body, _ := ioutil.ReadAll(resp.Body)
	var result CensysResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}
