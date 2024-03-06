package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ClarifaiAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Clarifai API keys, key to accessing Clarifai's AI services. Exposure risks unauthorized access and data breaches.",

		RuleID: "clarifai-api-token",

		Regex: generateSemiGenericRegex([]string{"clarifai"}, `[a-f0-9]{32}`, true),

		Keywords: []string{"clarifai", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("clarifai", secrets.NewSecret(hex("32"))),
	}
	return validate(r, tps, nil)
}
