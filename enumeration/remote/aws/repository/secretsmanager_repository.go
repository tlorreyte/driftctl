package repository

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/snyk/driftctl/enumeration/remote/cache"
)

type SMRepository interface {
	ListSecrets() ([]*string, error)
}

type smRepository struct {
	client *secretsmanager.SecretsManager
	cache  cache.Cache
}

func NewSMRepository(session *session.Session, c cache.Cache) *smRepository {
	return &smRepository{
		secretsmanager.New(session),
		c,
	}
}

func (s *smRepository) ListSecrets() ([]*string, error) {
	if v := s.cache.Get("smListSecrets"); v != nil {
		return v.([]*string), nil
	}

	var secrets []*string

	err := s.client.ListSecretsPages(&secretsmanager.ListSecretsInput{},
		func(page *secretsmanager.ListSecretsOutput, lastPage bool) bool {
			for _, secret := range page.SecretList {
				secrets = append(secrets, secret.ARN)
			}
			return !lastPage
		})
	if err != nil {
		return nil, err
	}

	s.cache.Put("smListSecrets", secrets)
	return secrets, nil
}
