package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func AnthropicAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Anthropics API keys, which if exposed, could compromise system integrity and data security.",

		RuleID: "anthropic-api-token",

		Regex: generateSemiGenericRegex([]string{"anthropic"}, `sk-ant-[A-Za-z0-9]{2,}-[A-Za-z0-9_-]{95}`, true),

		Keywords: []string{"anthropic", "api", "key", "sk-ant-"},
	}

	tps := []string{
		generateSampleSecret("anthropic", "sk-ant-"+secrets.NewSecret(alphaNumeric("2"))+"-"+secrets.NewSecret(alphaNumericExtendedShort("95"))),
	}
	return validate(r, tps, nil)
}
