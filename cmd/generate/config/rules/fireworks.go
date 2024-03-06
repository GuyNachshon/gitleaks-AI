package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func FireworksAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Fireworks API token",

		RuleID: "fireworks-api-token",

		Regex: generateSemiGenericRegex([]string{"fireworks"}, `[A-Za-z0-9]{48}`, true),

		Keywords: []string{"fireworks", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("fireworks", secrets.NewSecret(alphaNumeric("48"))),
	}
	return validate(r, tps, nil)
}
