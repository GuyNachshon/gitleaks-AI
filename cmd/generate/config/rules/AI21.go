package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AI21APIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects AI21 API keys, essential for accessing AI21's services. Key exposure could compromise service security.",

		RuleID: "ai21-api-token",

		Regex: generateSemiGenericRegex([]string{"ai21"}, `[A-Za-z0-9]{32}`, true),

		Keywords: []string{"AI21", "api", "key", "ai21"},
	}

	tps := []string{
		generateSampleSecret("ai21", secrets.NewSecret(alphaNumeric("32"))),
	}
	return validate(r, tps, nil)
}
