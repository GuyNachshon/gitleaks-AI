package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func CometAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Comet API keys, essential for accessing Comet's machine learning platform. Key exposure risks unauthorized access and potential data misuse.",

		RuleID: "comet-api-token",

		Regex: generateSemiGenericRegex([]string{"comet"}, `[A-Za-z0-9]{25}`, true),

		Keywords: []string{"comet", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("comet", secrets.NewSecret("HN6FbVyLBsdD2ghHb3zVCseHR")),
	}
	return validate(r, tps, nil)
}
