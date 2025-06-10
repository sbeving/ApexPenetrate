// internal/modules/reconnaissance/http_param_fuzzer.go
package reconnaissance

import (
	"apexPenetrateGo/internal/core"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type HTTPParamFuzzerResult struct {
	Target string
	Params []string
	Found  []string
}

func HTTPParamFuzzer(target string, params []string) *HTTPParamFuzzerResult {
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}
	found := []string{}
	for _, param := range params {
		u, _ := url.Parse(target)
		q := u.Query()
		q.Set(param, "fuzz")
		u.RawQuery = q.Encode()
		resp, err := http.Get(u.String())
		if err != nil {
			continue
		}
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(body), param) {
			found = append(found, param)
		}
	}
	return &HTTPParamFuzzerResult{Target: target, Params: params, Found: found}
}

func (r *HTTPParamFuzzerResult) String() string {
	return fmt.Sprintf("\n🔎 HTTP Param Fuzzer for %s:\n  Tested: %v\n  Found: %v\n", r.Target, r.Params, r.Found)
}

type httpParamFuzzerPlugin struct{}

func (p *httpParamFuzzerPlugin) Name() string        { return "HTTPParamFuzzer" }
func (p *httpParamFuzzerPlugin) Description() string { return "Fuzzes for hidden GET/POST parameters" }
func (p *httpParamFuzzerPlugin) Category() string    { return "recon" }
func (p *httpParamFuzzerPlugin) Options() []core.ModuleOption {
	return []core.ModuleOption{
		{Name: "params", Type: "string", Default: "debug,test,admin,id,user,q,search,lang,token", Description: "Comma-separated parameters to fuzz", Required: false},
	}
}
func (p *httpParamFuzzerPlugin) Run(target string, options map[string]interface{}) (interface{}, error) {
	params := []string{"debug", "test", "admin", "id", "user", "q", "search", "lang", "token"}
	if opt, ok := options["params"]; ok {
		if ps, ok := opt.([]string); ok {
			params = ps
		}
	}
	return HTTPParamFuzzer(target, params), nil
}

func init() {
	core.RegisterPlugin(&httpParamFuzzerPlugin{})
}
