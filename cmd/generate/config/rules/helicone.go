package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func HeliconeAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Helicone API keys, crucial for Helicone service access. Exposure risks unauthorized data access.",

		RuleID: "helicone-api-token",

		Regex: generateSemiGenericRegex([]string{"helicone"}, `sk-helicone-[a-zA-Z0-9]{7}-[a-zA-Z0-9]{7}-[a-zA-Z0-9]{7}-[a-zA-Z0-9]{7}`, true),

		Keywords: []string{"helicone", "api", "key", "sk-helicone-"},
	}

	tps := []string{
		generateSampleSecret("helicone", "sk-helicone-"+secrets.NewSecret(alphaNumeric("7"))+"-"+secrets.NewSecret(alphaNumeric("7"))+"-"+secrets.NewSecret(alphaNumeric("7"))+"-"+secrets.NewSecret(alphaNumeric("7"))),
	}
	return validate(r, tps, nil)
}
