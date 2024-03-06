package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func UptrainAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Uptrain API keys, essential for accessing Uptrain services. Exposure could lead to unauthorized access.",

		RuleID: "uptrain-api-token",

		Regex: generateSemiGenericRegex([]string{"uptrain"}, `up-[A-Za-z0-9_\-]{20,}`, true),

		Keywords: []string{"uptrain", "api", "key", "up-"},
	}

	tps := []string{
		generateSampleSecret("uptrain", "up-"+secrets.NewSecret(alphaNumericExtendedShort("20"))),
	}
	return validate(r, tps, nil)
}
