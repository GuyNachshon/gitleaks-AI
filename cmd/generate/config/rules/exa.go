package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ExaAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Exa API keys, essential for accessing Exa services. Key exposure risks unauthorized access.",

		RuleID: "exa-api-token",

		Regex: generateSemiGenericRegex([]string{"exa"}, `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`, true),

		Keywords: []string{"exa", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("exa", secrets.NewSecret(uuid())),
	}
	return validate(r, tps, nil)
}
