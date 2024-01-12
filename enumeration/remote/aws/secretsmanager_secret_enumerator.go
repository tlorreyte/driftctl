package aws

import (
	"github.com/snyk/driftctl/enumeration/remote/aws/repository"
	remoteerror "github.com/snyk/driftctl/enumeration/remote/error"
	"github.com/snyk/driftctl/enumeration/resource"
	"github.com/snyk/driftctl/enumeration/resource/aws"
)

type SMSecretEnumerator struct {
	repository repository.SMRepository
	factory    resource.ResourceFactory
}

func NewSMSecretEnumerator(repository repository.SMRepository, factory resource.ResourceFactory) *SMSecretEnumerator {
	return &SMSecretEnumerator{
		repository,
		factory,
	}
}

func (e *SMSecretEnumerator) SupportedType() resource.ResourceType {
	return aws.AwsSecretResourceType
}

func (e *SMSecretEnumerator) Enumerate() ([]*resource.Resource, error) {
	secrets, err := e.repository.ListSecrets()
	if err != nil {
		return nil, remoteerror.NewResourceListingError(err, string(e.SupportedType()))
	}

	results := make([]*resource.Resource, 0, len(secrets))

	for _, secret := range secrets {
		results = append(
			results,
			e.factory.CreateAbstractResource(
				string(e.SupportedType()),
				*secret,
				map[string]interface{}{
					"arn": *secret,
				},
			),
		)
	}

	return results, nil
}
