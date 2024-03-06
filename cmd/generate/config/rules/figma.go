package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func FigmaAccessToken() *config.Rule {
	r := config.Rule{
		Description: "Figma access token",

		RuleID: "figma-access-token",

		Regex: generateSemiGenericRegex([]string{"figma"}, `figd_[A-Za-z0-9\-_]{40}`, true),

		Keywords: []string{"figma", "api", "key", "access", "token", "figd_"},
	}

	tps := []string{
		generateSampleSecret("figma", "figd_"+secrets.NewSecret(alphaNumericExtendedShort("40"))),
	}
	return validate(r, tps, nil)
}
