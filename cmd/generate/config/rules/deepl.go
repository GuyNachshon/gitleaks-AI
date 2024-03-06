package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func DeepLAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects DeepL API tokens. These tokens allow users to access a wide range of language processing functionalities, exposing them could potentially lead to data privacy issues or unexpected charges.",

		RuleID: "deepl-api-token",

		Regex: generateSemiGenericRegex([]string{"deepl"}, `[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}:[a-z]{2}`, true),

		Keywords: []string{"deepl", "api", "token", ":fx"},
	}

	tps := []string{
		generateSampleSecret("deepl", secrets.NewSecret(uuid()+":fx")),
	}
	return validate(r, tps, nil)
}
