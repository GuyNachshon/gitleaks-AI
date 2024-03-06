package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GoldenAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Golden provides a set of natural language APIs for querying and enrichment using the Golden Knowledge Graph e.g. queries, exposure could lead to unauthorized access to sensitive data.",

		RuleID: "exa-api-token",

		Regex: generateSemiGenericRegex([]string{"golden"}, `[A-Z0-9]{26}`, true),

		Keywords: []string{"golden", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("golden", secrets.NewSecret("JFK302LJD5YE0PQW77YENW3JBD")),
	}
	return validate(r, tps, nil)
}
