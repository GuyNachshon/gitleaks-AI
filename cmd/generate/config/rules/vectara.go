package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func VectaraAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Vectara API keys, crucial for accessing Vectara services. Exposure risks unauthorized access and data breaches.",

		RuleID: "vectara-api-token",

		Regex: generateSemiGenericRegex([]string{"vectara"}, `z(w|u)t_[A-Za-z0-9\-_]{38}`, true),

		Keywords: []string{"vectara", "api", "key", "zwt_", "zut_"},
	}

	tps := []string{
		generateSampleSecret("vectara", "zwt_"+secrets.NewSecret(alphaNumericExtendedShort("38"))),
		generateSampleSecret("vectara", "zut_"+secrets.NewSecret(alphaNumericExtendedShort("38"))),
	}
	return validate(r, tps, nil)
}
