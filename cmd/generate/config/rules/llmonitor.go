package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LLMonitorAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects LLMonitor API keys, vital for accessing LLMonitor services. Key exposure could lead to unauthorized access.",

		RuleID: "llmonitor-api-token",

		Regex: generateSemiGenericRegex([]string{"llmonitor"}, `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`, true),

		Keywords: []string{"LLMonitor", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("llmonitor", secrets.NewSecret(uuid())),
	}
	return validate(r, tps, nil)
}
