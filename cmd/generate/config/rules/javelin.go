package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func JavelinAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Javelin API keys, vital for accessing Javelin services. Key exposure could lead to unauthorized service access.",

		RuleID: "javelin-api-token",

		Regex: generateSemiGenericRegex([]string{"javelin"}, `[A-Za-z0-9]{40}`, true),

		Keywords: []string{"javelin", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("javelin", secrets.NewSecret(alphaNumeric("40"))),
	}
	return validate(r, tps, nil)
}
