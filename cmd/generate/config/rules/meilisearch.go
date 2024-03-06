package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func MeiliSearch() *config.Rule {
	r := config.Rule{
		Description: "Detects Meilisearch API keys, essential for accessing Meilisearch services. Exposure risks unauthorized access.",

		RuleID: "meilisearch-api-token",

		Regex: generateSemiGenericRegex([]string{"meilisearch"}, `[a-f0-9]{64}`, true),

		Keywords: []string{"meilisearch", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("meilisearch", secrets.NewSecret(hex("64"))),
	}
	return validate(r, tps, nil)
}
