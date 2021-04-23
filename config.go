package dynamo

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

// Config dynamodb configuration parameters
type Config struct {
	AWSCONFIG        *aws.Config
	TABLE            *TableConfig
	ENDPOINT         string
	CONSISTENT_READS bool
}

type TableConfig struct {
	BasicCname   string
	AccessCName  string
	RefreshCName string
}

// NewConfig create dynamodb configuration
func NewConfig(region, endpoint, accessKey, secret, basicTableName, accessTableName, refreshTableName string) (config *Config, err error) {
	awsConfig := aws.NewConfig()
	if len(region) > 0 {
		awsConfig.Region = region
	}
	if len(accessKey) > 0 && len(secret) > 0 {
		awsConfig.Credentials = aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(accessKey, secret, ""))
	}
	if len(endpoint) > 0 {
		awsConfig.EndpointResolver = aws.EndpointResolverFunc(func(service, region string) (aws.Endpoint, error) {
			if service == dynamodb.ServiceID {
				return aws.Endpoint{
					PartitionID:   "aws",
					URL:           endpoint,
					SigningRegion: region,
				}, nil
			}
			// returning EndpointNotFoundError will allow the service to fallback to it's default resolution
			return aws.Endpoint{}, &aws.EndpointNotFoundError{}
		})
	}

	config = &Config{
		AWSCONFIG: awsConfig,
		TABLE: &TableConfig{
			BasicCname:   basicTableName,
			AccessCName:  accessTableName,
			RefreshCName: refreshTableName,
		},
		ENDPOINT: endpoint,
	}
	return
}
