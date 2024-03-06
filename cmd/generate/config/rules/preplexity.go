package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PreplexityAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Preplexity API keys, crucial for accessing its services. Exposure could lead to unauthorized access and data compromise.",

		RuleID: "preplexity-api-token",

		Regex: generateSemiGenericRegex([]string{"preplexity"}, `pplx-[a-f0-9]{48}`, true),

		Keywords: []string{"preplexity", "api", "key", "pplx-"},
	}

	tps := []string{
		generateSampleSecret("preplexity", "pplx-"+secrets.NewSecret(hex("48"))),
	}
	return validate(r, tps, nil)
}
