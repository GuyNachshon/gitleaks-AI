package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func ReplicateAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Replicate API keys, vital for accessing Replicate's services. Key exposure risks unauthorized service access.",

		RuleID: "replicate-api-token",

		Regex: generateSemiGenericRegex([]string{"replicate"}, `r8_[A-Za-z0-9_-]{37}`, true),

		Keywords: []string{"replicate", "api", "key", "r8_"},
	}

	tps := []string{
		generateSampleSecret("replicate", "r8_"+secrets.NewSecret(alphaNumericExtendedShort("37"))),
	}
	return validate(r, tps, nil)
}
