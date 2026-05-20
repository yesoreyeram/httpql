package secrets

import (
	"fmt"

	"github.com/yesoreyeram/httpql/internal/config"
)

// New returns the [Provider] appropriate for the given [config.SecretsConfig].
//
// Supported backend values:
//
//   - "env"     — reads plain environment variables (no extra config required)
//   - "vault"   — HashiCorp Vault KV v2 (requires security.secrets.vault config)
//   - "k8s"     — Kubernetes Secrets (requires security.secrets.k8s config)
//   - "aws-ssm" — AWS SSM Parameter Store (requires security.secrets.aws_ssm config)
//
// An error is returned when the selected backend's required credentials or
// configuration are not present at construction time.
func New(cfg config.SecretsConfig) (Provider, error) {
	switch cfg.Backend {
	case "env", "":
		return newEnvProvider(), nil
	case "vault":
		return newVaultProvider(cfg.Vault)
	case "k8s":
		return newK8sProvider(cfg.K8s)
	case "aws-ssm":
		return newAwsSsmProvider(cfg.AWSSSM)
	default:
		return nil, fmt.Errorf("secrets: unknown backend %q; must be env|vault|k8s|aws-ssm", cfg.Backend)
	}
}
