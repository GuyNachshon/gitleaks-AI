package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func GradientWorkspaceAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Uncovered a Gradient API Token, potentially compromising access to Gradient Workspace.",

		RuleID: "gradient-workspace-api-token",

		Regex: generateSemiGenericRegex([]string{"gradient"}, `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}_workspace`, true),

		Keywords: []string{"gradient", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("gradient", secrets.NewSecret(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}_workspace`)),
	}
	return validate(r, tps, nil)
}
