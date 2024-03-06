package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PredictionGuardAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects PredictionGuard API keys, essential for accessing predictionGuard services. Exposure risks unauthorized access.",

		RuleID: "predictionguard-api-token",

		Regex: generateSemiGenericRegex([]string{"predictionguard"}, `[A-Za-z0-9]{40}`, true),

		Keywords: []string{"predictionguard", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("predictionguard", secrets.NewSecret(alphaNumeric("40"))),
	}
	return validate(r, tps, nil)
}
