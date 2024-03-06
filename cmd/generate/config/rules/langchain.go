package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func LangChainAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Uncovered a Langchain API Token, potentially compromising access to the Langchain Service.",

		RuleID: "langchain-api-token",

		Regex: generateSemiGenericRegex([]string{"langchain"}, `ls__[a-f0-9]{32}`, true),

		Keywords: []string{"langchain", "api", "key", "ls__"},
	}

	tps := []string{
		generateSampleSecret("langchain", "ls__"+secrets.NewSecret(hex("32"))),
	}
	return validate(r, tps, nil)
}
