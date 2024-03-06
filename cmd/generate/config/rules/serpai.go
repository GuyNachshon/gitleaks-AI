package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func SerpAIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects serpAI API tokens, which are critical for authenticating and authorizing access to serpAI's search engine data scraping services. Unauthorized access to these tokens could lead to unauthorized data access, manipulation, or depletion of allocated query quotas, potentially impacting data integrity and service availability.",

		RuleID: "serpai-api-token",

		Regex: generateSemiGenericRegex([]string{"serpai"}, `[a-f0-9]{64}`, true),

		Keywords: []string{"serpai", "api", "token"},
	}

	tps := []string{
		generateSampleSecret("serpai", secrets.NewSecret(hex("64"))),
	}
	return validate(r, tps, nil)
}
