package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func CerebriumAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Cerebrium API keys, crucial for accessing specific services. Key exposure risks unauthorized access.",

		RuleID: "cerebrium-api-token",

		Regex: generateSemiGenericRegex([]string{"cerebrium"}, `private-[a-f0-9]{20}`, true),

		Keywords: []string{"cerebrium", "api", "key", "private-"},
	}

	tps := []string{
		generateSampleSecret("cerebrium", "private-"+secrets.NewSecret(hex("20"))),
	}
	return validate(r, tps, nil)
}
