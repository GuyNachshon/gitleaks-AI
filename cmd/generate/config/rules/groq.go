package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GroqAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Groq API keys, essential for accessing Groq services. Key exposure risks unauthorized access and data compromise.",

		RuleID: "groq-api-token",

		Regex: generateSemiGenericRegex([]string{"groq"}, `gsk_[A-Za-z0-9]{52}`, true),

		Keywords: []string{"groq", "api", "key", "gsk_"},
	}

	tps := []string{
		generateSampleSecret("groq", "gsk_"+secrets.NewSecret(alphaNumeric("52"))),
	}
	return validate(r, tps, nil)
}
