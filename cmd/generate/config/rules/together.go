package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func TogetherAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Together API keys, crucial for service access. Key exposure risks data and service integrity.",

		RuleID: "together-api-token",

		Regex: generateSemiGenericRegex([]string{"together"}, `[a-f0-9]{64}`, true),

		Keywords: []string{"together", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("together", secrets.NewSecret(hex("64"))),
	}
	return validate(r, tps, nil)
}
