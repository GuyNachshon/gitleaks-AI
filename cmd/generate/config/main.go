package main

import (
	"github.com/rs/zerolog/log"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
	"github.com/zricethezav/gitleaks/v8/config"
	"os"
	"text/template"
)

const (
	templatePath = "rules/config.tmpl"
)

//go:generate go run $GOFILE ../../../config/gitleaks.toml

func main() {
	if len(os.Args) < 2 {
		os.Stderr.WriteString("Specify path to the gitleaks.toml config\n")
		os.Exit(2)
	}
	gitleaksConfigPath := os.Args[1]

	configRules := []*config.Rule{
		rules.AdafruitAPIKey(),
		rules.AdobeClientID(),
		rules.AdobeClientSecret(),
		rules.AgeSecretKey(),
		rules.AI21APIKey(),
		rules.Airtable(),
		rules.AlgoliaApiKey(),
		rules.AlibabaAccessKey(),
		rules.AlibabaSecretKey(),
		rules.AnthropicAPIKey(),
		rules.AsanaClientID(),
		rules.AsanaClientSecret(),
		rules.Atlassian(),
		rules.Authress(),
		rules.AWS(),
		rules.BitBucketClientID(),
		rules.BitBucketClientSecret(),
		rules.BittrexAccessKey(),
		rules.BittrexSecretKey(),
		rules.Beamer(),
		rules.CerebriumAPIKey(),
		rules.CodecovAccessToken(),
		rules.CoinbaseAccessToken(),
		rules.ClarifaiAPIKey(),
		rules.ClearmlAPIKey(),
		rules.Clojars(),
		rules.CohereAPIKey(),
		//rules.CometAPIKey(),
		rules.ConfluentAccessToken(),
		rules.ConfluentSecretKey(),
		rules.Contentful(),
		rules.Databricks(),
		rules.DatadogtokenAccessToken(),
		rules.DeepInfraAPIKey(),
		rules.DeepLAPIKey(),
		rules.DefinedNetworkingAPIToken(),
		rules.DigitalOceanPAT(),
		rules.DigitalOceanOAuthToken(),
		rules.DigitalOceanRefreshToken(),
		rules.DiscordAPIToken(),
		rules.DiscordClientID(),
		rules.DiscordClientSecret(),
		rules.Doppler(),
		rules.DropBoxAPISecret(),
		rules.DropBoxLongLivedAPIToken(),
		rules.DropBoxShortLivedAPIToken(),
		rules.DroneciAccessToken(),
		rules.Duffel(),
		rules.Dynatrace(),
		rules.EasyPost(),
		rules.EasyPostTestAPI(),
		rules.EtsyAccessToken(),
		//rules.ExaAPIKey(),
		rules.Facebook(),
		rules.FastlyAPIToken(),
		rules.FigmaAccessToken(),
		rules.FinicityClientSecret(),
		rules.FinicityAPIToken(),
		rules.FireworksAPIKey(),
		rules.FlickrAccessToken(),
		rules.FinnhubAccessToken(),
		rules.FlowiseAPIKey(),
		rules.FlutterwavePublicKey(),
		rules.FlutterwaveSecretKey(),
		rules.FlutterwaveEncKey(),
		rules.FrameIO(),
		rules.FreshbooksAccessToken(),
		rules.GoCardless(),
		rules.GoldenAPIKey(),
		// TODO figure out what makes sense for GCP
		// rules.GCPServiceAccount(),
		rules.GCPAPIKey(),
		rules.GitHubPat(),
		rules.GitHubFineGrainedPat(),
		rules.GitHubOauth(),
		rules.GitHubApp(),
		rules.GitHubRefresh(),
		rules.GitlabPat(),
		rules.GitlabPipelineTriggerToken(),
		rules.GitlabRunnerRegistrationToken(),
		rules.GitterAccessToken(),
		rules.GrafanaApiKey(),
		rules.GrafanaCloudApiToken(),
		rules.GrafanaServiceAccountToken(),
		rules.GraphsignalAPIKey(),
		rules.GroqAPIKey(),
		rules.Hashicorp(),
		rules.HashicorpField(),
		rules.HeliconeAPIKey(),
		rules.Heroku(),
		rules.HubSpot(),
		rules.HuggingFaceAccessToken(),
		rules.HuggingFaceOrganizationApiToken(),
		rules.Intercom(),
		rules.JavelinAPIKey(),
		rules.JFrogAPIKey(),
		rules.JFrogIdentityToken(),
		rules.JinaAPIKey(),
		rules.JWT(),
		rules.JWTBase64(),
		rules.KonkoAPIKey(),
		rules.KrakenAccessToken(),
		rules.KucoinAccessToken(),
		rules.KucoinSecretKey(),
		rules.LangChainAPIKey(),
		rules.LaunchDarklyAccessToken(),
		rules.LinearAPIToken(),
		rules.LinearClientSecret(),
		rules.LinkedinClientID(),
		rules.LinkedinClientSecret(),
		rules.LLMonitorAPIKey(),
		rules.LobAPIToken(),
		rules.LobPubAPIToken(),
		rules.MailChimp(),
		rules.MailGunPubAPIToken(),
		rules.MailGunPrivateAPIToken(),
		rules.MailGunSigningKey(),
		rules.MapBox(),
		rules.MattermostAccessToken(),
		rules.MeiliSearch(),
		rules.MetalAPIKey(),
		rules.MessageBirdAPIToken(),
		rules.MessageBirdClientID(),
		rules.MistralAPIKey(),
		rules.NetlifyAccessToken(),
		rules.NewRelicUserID(),
		rules.NewRelicUserKey(),
		rules.NewRelicBrowserAPIKey(),
		rules.NPM(),
		rules.NytimesAccessToken(),
		rules.OktaAccessToken(),
		rules.OpenAI(),
		rules.PineconeAPIKey(),
		rules.PlaidAccessID(),
		rules.PlaidSecretKey(),
		rules.PlaidAccessToken(),
		rules.PlanetScalePassword(),
		rules.PlanetScaleAPIToken(),
		rules.PlanetScaleOAuthToken(),
		rules.PostManAPI(),
		rules.PredibaseAPIKey(),
		rules.PredictionGuardAPIKey(),
		rules.Prefect(),
		rules.PreplexityAPIKey(),
		rules.PrivateKey(),
		rules.PulumiAPIToken(),
		rules.PyPiUploadToken(),
		rules.RapidAPIAccessToken(),
		rules.ReadMe(),
		rules.ReplicateAPIKey(),
		rules.RubyGemsAPIToken(),
		rules.ScalingoAPIToken(),
		rules.SendbirdAccessID(),
		rules.SendbirdAccessToken(),
		rules.SendGridAPIToken(),
		rules.SendInBlueAPIToken(),
		rules.SentryAccessToken(),
		rules.SerpAIKey(),
		rules.ShippoAPIToken(),
		rules.ShopifyAccessToken(),
		rules.ShopifyCustomAccessToken(),
		rules.ShopifyPrivateAppAccessToken(),
		rules.ShopifySharedSecret(),
		rules.SidekiqSecret(),
		rules.SidekiqSensitiveUrl(),
		rules.SlackBotToken(),
		rules.SlackUserToken(),
		rules.SlackAppLevelToken(),
		rules.SlackConfigurationToken(),
		rules.SlackConfigurationRefreshToken(),
		rules.SlackLegacyBotToken(),
		rules.SlackLegacyWorkspaceToken(),
		rules.SlackLegacyToken(),
		rules.SlackWebHookUrl(),
		rules.Snyk(),
		rules.StripeAccessToken(),
		rules.SquareAccessToken(),
		rules.SquareSpaceAccessToken(),
		rules.SumoLogicAccessID(),
		rules.SumoLogicAccessToken(),
		rules.TavilyAPIKey(),
		rules.TeamsWebhook(),
		rules.TelegramBotToken(),
		rules.TogetherAPIKey(),
		rules.TravisCIAccessToken(),
		rules.Twilio(),
		rules.TwitchAPIToken(),
		rules.TwitterAPIKey(),
		rules.TwitterAPISecret(),
		rules.TwitterAccessToken(),
		rules.TwitterAccessSecret(),
		rules.TwitterBearerToken(),
		rules.Typeform(),
		rules.UptrainAPIKey(),
		rules.VaultBatchToken(),
		rules.VaultServiceToken(),
		rules.VectaraAPIKey(),
		rules.WandbAPIKey(),
		rules.WhylabsAPIKey(),
		rules.YandexAPIKey(),
		rules.YandexAWSAccessToken(),
		rules.YandexAccessToken(),
		rules.ZendeskSecretKey(),
		rules.GenericCredential(),
		rules.GradientWorkspaceAPIKey(),
		rules.InfracostAPIToken(),
	}

	// ensure rules have unique ids
	ruleLookUp := make(map[string]config.Rule, len(configRules))
	for _, rule := range configRules {
		// check if rule is in ruleLookUp
		if _, ok := ruleLookUp[rule.RuleID]; ok {
			log.Fatal().Msgf("rule id %s is not unique", rule.RuleID)
		}
		// TODO: eventually change all the signatures to get ride of this
		// nasty dereferencing.
		ruleLookUp[rule.RuleID] = *rule
	}

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse template")
	}

	f, err := os.Create(gitleaksConfigPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create rules.toml")
	}

	if err = tmpl.Execute(f, config.Config{Rules: ruleLookUp}); err != nil {
		log.Fatal().Err(err).Msg("could not execute template")
	}

}
