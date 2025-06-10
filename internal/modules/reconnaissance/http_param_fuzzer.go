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

func (p *httpParamFuzzerPlugin) Help() string {
	return `
🔍 HTTP Parameter Fuzzer - Hidden Parameter Discovery Tool

DESCRIPTION:
  Discovers hidden HTTP parameters by fuzzing GET/POST requests with common
  parameter names. Essential for finding debug parameters and hidden functionality.

USAGE:
  httpparamfuzzer <target_url> [options]

OPTIONS:
  params - Comma-separated list of parameters to test (optional)

EXAMPLES:
  httpparamfuzzer https://example.com/search
  httpparamfuzzer https://api.example.com --params debug,admin,test
  httpparamfuzzer https://example.com/login

ATTACK SCENARIOS:
  • Debug Parameter Discovery: Find development/debug parameters
  • Hidden Functionality: Uncover undocumented API endpoints
  • Admin Features: Discover administrative parameters
  • Bypass Mechanisms: Find parameters that alter application behavior

COMMON PARAMETERS:
  • Debug: debug, test, dev, verbose, trace
  • Admin: admin, administrator, root, su
  • Authentication: token, key, auth, session
  • Control: action, cmd, command, exec
  • Filtering: filter, search, query, q

PRO TIPS:
  💡 Monitor response size differences for parameter acceptance
  💡 Check for different HTTP status codes
  💡 Look for error message changes indicating parameter recognition
  💡 Test both GET and POST parameter injection
  💡 Use wordlists specific to discovered technology stack
  💡 Check for reflected parameter values in responses

DETECTION METHODS:
  • Response Length Analysis
  • Status Code Differences
  • Error Message Variations
  • Response Time Analysis
  • Content-Type Changes

RISK LEVEL: Medium (information disclosure, hidden functionality)
`
}

func init() {
	core.RegisterPlugin(&httpParamFuzzerPlugin{})
}
