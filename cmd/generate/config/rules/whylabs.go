package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func WhylabsAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Whylabs API keys, essential for accessing Whylabs services. Key exposure risks unauthorized access and data compromise.",

		RuleID: "whylabs-api-token",

		Regex: generateSemiGenericRegex([]string{"whylabs"}, `[A-Za-z0-9\.]{64}:org-[A-Za-z0-9]+`, true),

		Keywords: []string{"whylabs", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("whylabs", secrets.NewSecret(alphaNumeric("64")+":org-"+alphaNumeric("6"))),
	}
	return validate(r, tps, nil)
}
