package reconnaissance

import (
	"net/http"
)

type HTTPReconResult struct {
	Headers map[string][]string
	Status  int
}

func HTTPRecon(target string) (*HTTPReconResult, error) {
	resp, err := http.Get(target)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return &HTTPReconResult{
		Headers: resp.Header,
		Status:  resp.StatusCode,
	}, nil
}
