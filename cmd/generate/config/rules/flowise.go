package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func FlowiseAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Uncovered a Flowise API Token, potentially compromising access to Flowise and exposes other secrets",

		RuleID: "flowise-api-token",

		Regex: generateSemiGenericRegex([]string{"flowise"}, `[A-Za-z0-9+/]{43,}={0,2}`, true),

		Keywords: []string{"flowise", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("flowise", secrets.NewSecret(`[A-Za-z0-9+/]{43,}={0,2}`)),
	}
	return validate(r, tps, nil)
}
