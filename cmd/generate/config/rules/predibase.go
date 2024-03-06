package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PredibaseAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Predibase API keys, crucial for accessing Predibase services. Key exposure could lead to unauthorized access.",

		RuleID: "predibase-api-token",

		Regex: generateSemiGenericRegex([]string{"predibase"}, `pb_[A-Za-z0-9]{22}`, true),

		Keywords: []string{"predibase", "api", "key", "pb_"},
	}

	tps := []string{
		generateSampleSecret("predibase", "pb_"+secrets.NewSecret(alphaNumeric("22"))),
	}
	return validate(r, tps, nil)
}
