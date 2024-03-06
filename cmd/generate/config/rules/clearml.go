package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ClearmlAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects ClearML API keys, crucial for accessing ClearML services. Exposure risks unauthorized system access.",

		RuleID: "clearml-api-token",

		Regex: generateSemiGenericRegex([]string{"clearml"}, `[A-Za-z0-9]{50}`, true),

		Keywords: []string{"clearml", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("clearml", secrets.NewSecret(alphaNumeric("50"))),
	}
	return validate(r, tps, nil)
}
