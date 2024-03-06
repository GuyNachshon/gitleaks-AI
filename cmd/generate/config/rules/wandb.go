package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func WandbAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Weights & Biases (wandb) API tokens. These tokens are crucial for authentication and unauthorized access could lead to potential misuse of the wandb services, compromising the integrity of machine learning experiments and data.",

		RuleID: "wandb-api-token",

		Regex: generateSemiGenericRegex([]string{"wandb"}, `[a-f0-9]{40}`, true),

		Keywords: []string{"wandb", "api", "key", "token"},
	}

	tps := []string{
		generateSampleSecret("wandb", secrets.NewSecret(hex("40"))),
	}
	return validate(r, tps, nil)
}
