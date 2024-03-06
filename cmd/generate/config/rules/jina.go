package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func JinaAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Jina API keys, essential for accessing Jina's services. Key exposure risks unauthorized access.",

		RuleID: "jina-api-token",

		Regex: generateSemiGenericRegex([]string{"jina"}, `jina_[A-Za-z0-9\-_]{59}`, true),

		Keywords: []string{"jina", "api", "key", "jina_"},
	}

	tps := []string{
		generateSampleSecret("jina", "jina_"+secrets.NewSecret(alphaNumericExtendedShort("59"))),
	}
	return validate(r, tps, nil)
}
