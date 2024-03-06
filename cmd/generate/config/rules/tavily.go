package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func TavilyAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects TAVILY API keys used for service access.",

		RuleID: "tavily-api-token",

		Regex: generateSemiGenericRegex([]string{"tavily"}, `tvly-[A-Za-z0-9]{32}`, true),

		Keywords: []string{"tavily", "api", "key", "tvly-"},
	}

	tps := []string{
		generateSampleSecret("tavily", secrets.NewSecret("tvly-"+secrets.NewSecret(alphaNumeric("32")))),
	}
	return validate(r, tps, nil)
}
