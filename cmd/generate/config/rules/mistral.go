package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MistralAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Mistral API keys, which if exposed, could lead to unauthorized access and potential data breaches.",

		RuleID: "mistral-api-token",

		Regex: generateSemiGenericRegex([]string{"mistral"}, `[A-Za-z0-9]{32}`, true),

		Keywords: []string{"mistral", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("mistral", secrets.NewSecret(alphaNumeric("32"))),
	}
	return validate(r, tps, nil)
}
