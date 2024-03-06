package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MetalAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Metal API keys, crucial for accessing Metal services. Exposure risks unauthorized access.",

		RuleID: "metal-api-token",

		Regex: generateSemiGenericRegex([]string{"metal"}, `[A-Za-z0-9]{32}`, true),

		Keywords: []string{"metal", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("metal", secrets.NewSecret(alphaNumeric("32"))),
	}
	return validate(r, tps, nil)
}
