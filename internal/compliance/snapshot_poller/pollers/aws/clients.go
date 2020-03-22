package aws

/**
 * Panther is a scalable, powerful, cloud-native SIEM written in Golang/React.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"go.uber.org/zap"

	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
)

const (
	// The amount of time credentials are valid
	assumeRoleDuration = time.Hour
	// Allows the credentials to trigger refreshing prior to the credentials actually expiring
	assumeRoleExpiryWindow = 5 * time.Second
	// retries on default session
	maxRetries = 6
)

var (
	newSessionFunc = newSession

	// assumeRoleFunc is the function to return valid AWS credentials.
	assumeRoleFunc = assumeRole
	// assumeRoleProviderFunc is the default function to setup the assume role provider.
	assumeRoleProviderFunc = assumeRoleProvider
)

var sessionCache = make(map[string]*session.Session)

func newSession(region string) (sess *session.Session) {
	if sess = sessionCache[region]; sess != nil {
		return sess
	}

	sess = session.Must(session.NewSession(&aws.Config{
		Region:     aws.String(region),
		MaxRetries: aws.Int(maxRetries)}))
	sessionCache[region] = sess
	return sess
}

// Key used for the client cache to neatly encapsulate an integration, service, and region
type clientKey struct {
	IntegrationID string
	Service       string
	Region        string
}

type cachedClient struct {
	Client      interface{}
	Credentials *credentials.Credentials
}

var clientCache = make(map[clientKey]cachedClient)

// Functions used to build clients, keyed by service, use function not map to allow late binding by tests
func lookupClientFunc(service string) func(session2 *session.Session, config *aws.Config) interface{} {
	switch service {
	case "acm":
		return AcmClientFunc
	case "applicationautoscaling":
		return ApplicationAutoScalingClientFunc
	case "cloudformation":
		return CloudFormationClientFunc
	case "cloudtrail":
		return CloudTrailClientFunc
	case "cloudwatchlogs":
		return CloudWatchLogsClientFunc
	case "configservice":
		return ConfigServiceClientFunc
	case "dynamodb":
		return DynamoDBClientFunc
	case "ec2":
		return EC2ClientFunc
	case "ecs":
		return EcsClientFunc
	case "elbv2":
		return Elbv2ClientFunc
	case "guardduty":
		return GuardDutyClientFunc
	case "iam":
		return IAMClientFunc
	case "kms":
		return KmsClientFunc
	case "lambda":
		return LambdaClientFunc
	case "rds":
		return RDSClientFunc
	case "redshift":
		return RedshiftClientFunc
	case "s3":
		return S3ClientFunc
	case "waf":
		return WafClientFunc
	case "waf-regional":
		return WafRegionalClientFunc
	default:
		return nil
	}
}

// getClient returns a valid client for a given integration, service, and region using caching.
func getClient(pollerInput *awsmodels.ResourcePollerInput, service string, region string) interface{} {
	cacheKey := clientKey{
		IntegrationID: *pollerInput.IntegrationID,
		Service:       service,
		Region:        region,
	}

	// Return the cached client if the credentials used to build it are not expired
	if cachedClient, exists := clientCache[cacheKey]; exists {
		if !cachedClient.Credentials.IsExpired() {
			if cachedClient.Client != nil {
				return cachedClient.Client
			}
			zap.L().Debug("expired client was cached", zap.Any("cache key", cacheKey))
		}
	}

	// Build a new client on cache miss OR if the client in the cache has expired credentials

	// Build the new session and credentials
	sess := newSessionFunc(region)
	creds := assumeRoleFunc(pollerInput, sess)

	// Build the new client and cache it with the credentials used to build it
	if clientFunc := lookupClientFunc(service); clientFunc != nil {
		client := clientFunc(sess, &aws.Config{Credentials: creds})
		clientCache[cacheKey] = cachedClient{
			Client:      client,
			Credentials: creds,
		}
		return client
	}

	zap.L().Error("cannot build client for unsupported service",
		zap.String("service", service),
	)
	return nil
}

// assumeRoleProvider configures the AssumeRole provider parameters to pass into STS.
func assumeRoleProvider() func(p *stscreds.AssumeRoleProvider) {
	return func(p *stscreds.AssumeRoleProvider) {
		p.Duration = assumeRoleDuration
		p.ExpiryWindow = assumeRoleExpiryWindow
	}
}

//  assumes an IAM role associated with an AWS Snapshot Integration.
func assumeRole(
	pollerInput *awsmodels.ResourcePollerInput,
	sess *session.Session,
) *credentials.Credentials {

	zap.L().Debug("assuming role", zap.String("roleArn", *pollerInput.AuthSource))

	if pollerInput.AuthSource == nil {
		panic("must pass non-nil authSource to AssumeRole")
	}

	creds := stscreds.NewCredentials(
		sess,
		*pollerInput.AuthSource,
		assumeRoleProviderFunc(),
	)

	return creds
}
