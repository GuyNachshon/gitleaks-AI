package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GraphsignalAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Graphsignal API keys, crucial for accessing Graphsignal services. Exposure risks unauthorized access.",

		RuleID: "graphsignal-api-token",

		Regex: generateSemiGenericRegex([]string{"graphsignal"}, `[a-f0-9]{32}`, true),

		Keywords: []string{"graphsignal", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("graphsignal", secrets.NewSecret(hex("32"))),
	}
	return validate(r, tps, nil)
}
