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
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/configservice/configserviceiface"
	"go.uber.org/zap"

	apimodels "github.com/panther-labs/panther/api/gateway/resources/models"
	awsmodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/aws"
	pollermodels "github.com/panther-labs/panther/internal/compliance/snapshot_poller/models/poller"
	"github.com/panther-labs/panther/internal/compliance/snapshot_poller/pollers/utils"
)

// Set as variables to be overridden in testing
var (
	ConfigServiceClientFunc = setupConfigServiceClient
)

func setupConfigServiceClient(sess *session.Session, cfg *aws.Config) interface{} {
	return configservice.New(sess, cfg)
}

// PollConfigService polls a single AWS Config resource
func PollConfigService(
	pollerResourceInput *awsmodels.ResourcePollerInput,
	parsedResourceID *utils.ParsedResourceID,
	scanRequest *pollermodels.ScanEntry) interface{} {

	client := getClient(pollerResourceInput, "configservice", parsedResourceID.Region).(configserviceiface.ConfigServiceAPI)
	recorder := getConfigRecorder(client)
	snapshot := buildConfigServiceSnapshot(client, recorder, parsedResourceID.Region)
	if snapshot == nil {
		return nil
	}
	snapshot.ResourceID = scanRequest.ResourceID
	snapshot.AccountID = aws.String(pollerResourceInput.AuthSourceParsedARN.AccountID)
	return snapshot
}

// getConfigRecorder returns a specific config recorder
func getConfigRecorder(svc configserviceiface.ConfigServiceAPI) *configservice.ConfigurationRecorder {
	recorder, err := svc.DescribeConfigurationRecorders(&configservice.DescribeConfigurationRecordersInput{
		ConfigurationRecorderNames: []*string{aws.String("default")},
	})
	if err != nil {
		if awsErr, ok := err.(awserr.Error); ok {
			if awsErr.Code() == "NoSuchConfigurationRecorderException" {
				zap.L().Warn("tried to scan non-existent resource",
					zap.String("resourceType", awsmodels.ConfigServiceSchema))
				return nil
			}
		}
		utils.LogAWSError("ConfigService.DescribeConfigurationRecorders", err)
		return nil
	}

	return recorder.ConfigurationRecorders[0]
}

// describeConfigurationRecorders returns a slice of all config recorders in the given region/account
func describeConfigurationRecorders(
	configServiceSvc configserviceiface.ConfigServiceAPI,
) ([]*configservice.ConfigurationRecorder, error) {

	recorders, err := configServiceSvc.DescribeConfigurationRecorders(
		&configservice.DescribeConfigurationRecordersInput{},
	)
	if err != nil {
		utils.LogAWSError("ConfigService.DescribeConfigurationRecorderStatus", err)
		return nil, err
	}

	return recorders.ConfigurationRecorders, nil
}

// describeConfigurationRecorderStatus returns the status of the given configuration recorder
func describeConfigurationRecorderStatus(
	configServiceSvc configserviceiface.ConfigServiceAPI, name *string,
) (*configservice.ConfigurationRecorderStatus, error) {

	in := &configservice.DescribeConfigurationRecorderStatusInput{
		ConfigurationRecorderNames: []*string{
			name,
		},
	}
	status, err := configServiceSvc.DescribeConfigurationRecorderStatus(in)
	if err != nil {
		utils.LogAWSError("ConfigService.DescribeConfigurationRecorderStatus", err)
		return nil, err
	}

	if status.ConfigurationRecordersStatus != nil && len(status.ConfigurationRecordersStatus) > 0 {
		return status.ConfigurationRecordersStatus[0], nil
	}
	return nil, nil
}

// buildConfigServiceSnapshot makes the required calls to build a ConfigServiceSnapshot object
func buildConfigServiceSnapshot(
	configServiceSvc configserviceiface.ConfigServiceAPI,
	recorder *configservice.ConfigurationRecorder,
	regionID string,
) *awsmodels.ConfigService {

	if recorder == nil {
		return nil
	}

	configSnapshot := &awsmodels.ConfigService{
		GenericResource: awsmodels.GenericResource{
			ResourceType: aws.String(awsmodels.ConfigServiceSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			Name:   recorder.Name,
			Region: &regionID,
		},
		RecordingGroup: recorder.RecordingGroup,
		RoleARN:        recorder.RoleARN,
	}

	status, err := describeConfigurationRecorderStatus(configServiceSvc, recorder.Name)
	if err != nil {
		utils.LogAWSError("ConfigService.DescribeStatus", err)
	} else {
		configSnapshot.Status = status
	}

	return configSnapshot
}

// PollConfigServices gathers information on each config service for an AWS account.
func PollConfigServices(pollerInput *awsmodels.ResourcePollerInput) ([]*apimodels.AddResourceEntry, error) {
	zap.L().Debug("starting ConfigService poller")
	configSnapshots := make(map[string]*awsmodels.ConfigService)

	for _, regionID := range utils.GetServiceRegions(pollerInput.Regions, "config") {
		zap.L().Debug("building Config snapshots", zap.String("region", *regionID))
		configServiceSvc := getClient(pollerInput, "configservice", *regionID).(configserviceiface.ConfigServiceAPI)

		// Start with generating a list of all recorders
		recorders, describeErr := describeConfigurationRecorders(configServiceSvc)
		if describeErr != nil {
			utils.LogAWSError("ConfigService.Describe", describeErr)
			continue
		}

		for _, recorder := range recorders {
			configServiceSnapshot := buildConfigServiceSnapshot(configServiceSvc, recorder, *regionID)
			if configServiceSnapshot == nil {
				continue
			}
			configServiceSnapshot.AccountID = aws.String(pollerInput.AuthSourceParsedARN.AccountID)

			resourceID := utils.GenerateResourceID(
				pollerInput.AuthSourceParsedARN.AccountID,
				*regionID,
				awsmodels.ConfigServiceSchema,
			)
			configServiceSnapshot.ResourceID = aws.String(resourceID)

			if _, ok := configSnapshots[resourceID]; !ok {
				configSnapshots[resourceID] = configServiceSnapshot
			} else {
				zap.L().Info(
					"overwriting existing ConfigService snapshot", zap.String("resourceId", resourceID))
				configSnapshots[resourceID] = configServiceSnapshot
			}
		}
	}

	configMetaSnapshot := &awsmodels.ConfigServiceMeta{
		GenericResource: awsmodels.GenericResource{
			ResourceType: aws.String(awsmodels.ConfigServiceMetaSchema),
		},
		GenericAWSResource: awsmodels.GenericAWSResource{
			AccountID: aws.String(pollerInput.AuthSourceParsedARN.AccountID),
			Name:      aws.String(awsmodels.ConfigServiceMetaSchema),
			Region:    aws.String(awsmodels.GlobalRegion),
		},
		GlobalRecorderCount: aws.Int(0),
		Recorders:           []*string{},
	}

	resources := make([]*apimodels.AddResourceEntry, 0, len(configSnapshots)+1)
	for resourceID, configSnapshot := range configSnapshots {
		configMetaSnapshot.Recorders = append(configMetaSnapshot.Recorders, aws.String(resourceID))
		if *configSnapshot.RecordingGroup.AllSupported && *configSnapshot.RecordingGroup.IncludeGlobalResourceTypes {
			*configMetaSnapshot.GlobalRecorderCount++
		}

		resources = append(resources, &apimodels.AddResourceEntry{
			Attributes:      configSnapshot,
			ID:              apimodels.ResourceID(resourceID),
			IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
			IntegrationType: apimodels.IntegrationTypeAws,
			Type:            awsmodels.ConfigServiceSchema,
		})
	}

	configMetaSnapshot.GlobalRecorderCount = aws.Int(len(resources))
	configMetaResourceID := utils.GenerateResourceID(
		pollerInput.AuthSourceParsedARN.AccountID,
		"",
		awsmodels.ConfigServiceMetaSchema,
	)
	configMetaSnapshot.ResourceID = aws.String(configMetaResourceID)

	resources = append(resources, &apimodels.AddResourceEntry{
		Attributes:      configMetaSnapshot,
		ID:              apimodels.ResourceID(configMetaResourceID),
		IntegrationID:   apimodels.IntegrationID(*pollerInput.IntegrationID),
		IntegrationType: apimodels.IntegrationTypeAws,
		Type:            awsmodels.ConfigServiceMetaSchema,
	})

	return resources, nil
}
