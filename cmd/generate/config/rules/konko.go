package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func KonkoAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Konko API keys, crucial for accessing Konko services. Exposure risks unauthorized access.",

		RuleID: "konko-api-token",

		Regex: generateSemiGenericRegex([]string{"konko"}, `ko-[A-Za-z0-9\-_]{48}`, true),

		Keywords: []string{"konko", "api", "key", "ko-"},
	}

	tps := []string{
		generateSampleSecret("konko", "ko-"+secrets.NewSecret(alphaNumericExtendedShort("48"))),
	}
	return validate(r, tps, nil)
}
