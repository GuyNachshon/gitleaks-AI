package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func CohereAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Cohere API keys, essential for accessing Cohere's AI and NLP services. Exposure poses a risk of unauthorized usage.",

		RuleID: "cohere-api-token",

		Regex: generateSemiGenericRegex([]string{"cohere"}, `[A-Za-z0-9]{40}`, true),

		Keywords: []string{"cohere", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("cohere", secrets.NewSecret(alphaNumeric("40"))),
	}
	return validate(r, tps, nil)
}
