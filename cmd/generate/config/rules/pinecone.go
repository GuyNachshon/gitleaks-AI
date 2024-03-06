package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

func PineconeAPIKey() *config.Rule {
	r := config.Rule{
		Description: "Detects Pinecone API keys, essential for accessing Pinecone services. Exposure could lead to unauthorized access.",

		RuleID: "pinecone-api-token",

		Regex: generateSemiGenericRegex([]string{"pinecone"}, `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`, true),

		Keywords: []string{"pinecone", "api", "key"},
	}

	tps := []string{
		generateSampleSecret("pinecone", secrets.NewSecret(uuid())),
	}
	return validate(r, tps, nil)
}
