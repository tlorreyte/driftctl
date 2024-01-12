package aws

import (
	"github.com/sirupsen/logrus"
	"github.com/snyk/driftctl/enumeration/resource"
	dctlresource "github.com/snyk/driftctl/pkg/resource"
)

const AwsSecretResourceType = "aws_secretsmanager_secret"

func initAwsSecretMetaData(resourceSchemaRepository dctlresource.SchemaRepositoryInterface) {
	resourceSchemaRepository.SetNormalizeFunc(AwsIamRoleResourceType, func(res *resource.Resource) {
		val := res.Attrs
		logrus.Info(res.Attrs)
		val.SafeDelete([]string{"rotation_enabled"})
		val.SafeDelete([]string{"rotation_rules"})
		val.SafeDelete([]string{"rotation_lambda_arn"})
	})
}
