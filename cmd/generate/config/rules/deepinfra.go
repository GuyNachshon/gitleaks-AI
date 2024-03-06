package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DeepInfraAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects deepinfra API keys, essential for accessing deepinfra's machine learning platform. Key exposure risks unauthorized access and potential data misuse.",

		RuleID: "comet-api-token",

		Regex: generateSemiGenericRegex([]string{"deepinfra"}, `[A-Za-z0-9]{32}`, true),

		Keywords: []string{"deepinfra", "api", "key", "deepInfra"},
	}

	tps := []string{
		generateSampleSecret("deepinfra", secrets.NewSecret(alphaNumeric("32"))),
	}
	return validate(r, tps, nil)
}
