package api

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
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/source/models"
)

var (
	// Formatting variables used for re-writing the default templates
	accountIDFind    = "Default: '' # MasterAccountId"
	accountIDReplace = "Default: %s # MasterAccountId"
	regionFind       = "Default: '' # MasterAccountRegion"
	regionReplace    = "Default: %s # MasterAccountRegion"

	// Formatting variables for Cloud Security
	cweFind            = "Default: false # DeployCloudWatchEventSetup"
	cweReplace         = "Default: %t # DeployCloudWatchEventSetup"
	remediationFind    = "Default: false # DeployRemediation"
	remediationReplace = "Default: %t # DeployRemediation"

	// Formatting variables for Log Analysis
	s3BucketFind    = "Default: '' # S3Buckets"
	s3BucketReplace = "Default: %s # S3Buckets"
	kmsKeyFind      = "Default: '' # EncryptionKeys"
	kmsKeyReplace   = "Default: %s # EncryptionKeys"
)

// GetIntegrationTemplate generates a new satellite account CloudFormation template based on the given parameters.
func (API) GetIntegrationTemplate(input *models.GetIntegrationTemplateInput) (*models.SourceIntegrationTemplate, error) {
	zap.L().Debug("constructing source template")

	// Format the template with the user's input
	formattedTemplate := strings.Replace(getTemplate(input.IntegrationType), accountIDFind,
		fmt.Sprintf(accountIDReplace, *input.AWSAccountID), 1)
	formattedTemplate = strings.Replace(formattedTemplate, regionFind,
		fmt.Sprintf(regionReplace, *sess.Config.Region), 1)

	// Cloud Security replacements
	formattedTemplate = strings.Replace(formattedTemplate, cweFind,
		fmt.Sprintf(cweReplace, *input.CWEEnabled), 1)
	formattedTemplate = strings.Replace(formattedTemplate, remediationFind,
		fmt.Sprintf(remediationReplace, *input.RemediationEnabled), 1)

	// Log Analysis replacements
	formattedTemplate = strings.Replace(formattedTemplate, s3BucketFind,
		fmt.Sprintf(s3BucketReplace, strings.Join(sliceStringValue(input.S3Buckets), ",")), 1)
	formattedTemplate = strings.Replace(formattedTemplate, kmsKeyFind,
		fmt.Sprintf(kmsKeyReplace, strings.Join(sliceStringValue(input.KmsKeys), ",")), 1)

	return &models.SourceIntegrationTemplate{
		Body: aws.String(formattedTemplate),
	}, nil
}

func sliceStringValue(stringPointers []*string) []string {
	out := make([]string, 0, len(stringPointers))
	for index, ptr := range stringPointers {
		out[index] = aws.StringValue(ptr)
	}
	return out
}

func getTemplate(integrationType *string) string {
	switch *integrationType {
	case models.IntegrationTypeAWSScan:
		return complianceTemplate
	case models.IntegrationTypeAWS3:
		return logProcessingTemplate
	default:
		panic("unknown integration type: " + *integrationType)
	}
}
