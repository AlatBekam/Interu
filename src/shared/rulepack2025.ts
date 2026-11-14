import type { RuleSeverity, Template } from './rules'

/** Six common backup names for 50 concrete configuration artifacts. Each rule
 * requires a product-specific body marker as well as HTTP 200. Detection proves
 * the backup is reachable; it does not claim the product is vulnerable to a CVE. */
type Source = [id: string, path: string, marker: string, severity: RuleSeverity]
const SOURCES: Source[] = [
  // Application configuration
  ['rails-secrets', '/config/secrets.yml', 'secret_key_base\\s*:', 'high'],
  ['rails-devise', '/config/initializers/devise.rb', 'Devise\\.setup\\s+do', 'medium'],
  ['rails-mongoid', '/config/mongoid.yml', 'development\\s*:[\\s\\S]*hosts\\s*:', 'medium'],
  ['rails-redis', '/config/redis.yml', 'redis\\s*:', 'medium'],
  ['rails-cable', '/config/cable.yml', 'adapter\\s*:', 'low'],
  ['rails-storage', '/config/storage.yml', 'service\\s*:', 'medium'],
  ['rails-sidekiq', '/config/sidekiq.yml', ':concurrency\\s*:', 'low'],
  ['rails-schedule', '/config/schedule.rb', 'every\\s+[:\\d]', 'low'],
  ['rails-webpacker', '/config/webpacker.yml', 'source_path\\s*:', 'low'],
  ['rails-puma', '/config/puma.rb', 'workers\\s+(?:ENV|\\d)', 'low'],
  ['django-local', '/settings_local.py', '(?:SECRET_KEY|DATABASES)\\s*=', 'high'],
  ['django-prod', '/project/settings/production.py', '(?:SECRET_KEY|DATABASES)\\s*=', 'high'],
  ['flask-config', '/instance/config.py', '(?:SECRET_KEY|SQLALCHEMY_DATABASE_URI)\\s*=', 'high'],
  ['laravel-auth', '/config/auth.php', "'defaults'\\s*=>", 'medium'],
  ['laravel-database', '/config/database.php', "'connections'\\s*=>", 'high'],
  ['laravel-mail', '/config/mail.php', "'mailers'\\s*=>", 'medium'],
  ['laravel-filesystems', '/config/filesystems.php', "'disks'\\s*=>", 'medium'],
  ['symfony-services', '/config/services.yaml', 'services\\s*:', 'medium'],
  ['symfony-packages', '/config/packages/security.yaml', 'security\\s*:', 'medium'],
  ['aspnet-prod', '/appsettings.Production.json', '"(?:ConnectionStrings|Logging|AllowedHosts)"\\s*:', 'high'],
  // Build and deployment
  ['npmrc', '/.npmrc', '(?:_authToken|registry)\\s*=', 'high'],
  ['pypirc', '/.pypirc', '\\[distutils\\]', 'high'],
  ['m2-settings', '/.m2/settings.xml', '<settings[\\s>]', 'high'],
  ['gradle-props', '/gradle.properties', '(?:org\\.gradle\\.|systemProp\\.)', 'medium'],
  ['docker-compose', '/docker-compose.yml', '(?:services|version)\\s*:', 'medium'],
  ['compose-prod', '/compose.prod.yaml', 'services\\s*:', 'medium'],
  ['helm-values', '/helm/values.yaml', '(?:image|replicaCount)\\s*:', 'medium'],
  ['helm-chart', '/charts/app/Chart.yaml', 'apiVersion\\s*:\\s*v2', 'low'],
  ['kustomization', '/kustomization.yaml', '(?:apiVersion\\s*:\\s*kustomize|kind\\s*:\\s*Kustomization)', 'medium'],
  ['tfvars', '/terraform.tfvars', '(?:region|instance_type|access_key|secret_key)\\s*=', 'high'],
  ['tf-backend', '/backend.tf', 'backend\\s+"', 'medium'],
  ['terragrunt', '/terragrunt.hcl', 'terraform\\s*\\{', 'medium'],
  ['packer', '/packer.json', '"builders"\\s*:', 'medium'],
  ['ansible-inventory', '/inventory.ini', '(?:\\[webservers\\]|\\[dbservers\\]|ansible_host\\s*=)', 'medium'],
  ['ansible-vars', '/group_vars/all.yml', '(?:ansible_user|ansible_password|become_pass)\\s*:', 'high'],
  ['github-deploy', '/.github/workflows/deploy.yml', '(?:jobs|runs-on)\\s*:', 'medium'],
  ['gitlab-ci', '/.gitlab-ci.yml', '(?:stages|image)\\s*:', 'medium'],
  ['buildkite', '/.buildkite/pipeline.yml', '(?:steps|command)\\s*:', 'medium'],
  ['argocd-app', '/argocd/application.yaml', 'kind\\s*:\\s*Application', 'medium'],
  ['skaffold', '/skaffold.yaml', 'apiVersion\\s*:\\s*skaffold', 'low'],
  // Infrastructure and service configuration
  ['k8s-secret', '/k8s/secret.yaml', 'kind\\s*:\\s*Secret', 'high'],
  ['k8s-deployment', '/k8s/deployment.yaml', 'kind\\s*:\\s*Deployment', 'medium'],
  ['prometheus', '/prometheus.yml', 'scrape_configs\\s*:', 'medium'],
  ['grafana-provision', '/provisioning/datasources/default.yaml', 'datasources\\s*:', 'medium'],
  ['nginx-config', '/nginx.conf', '(?:server|http)\\s*\\{', 'medium'],
  ['apache-vhost', '/sites-available/000-default.conf', '<VirtualHost\\s', 'medium'],
  ['redis-config', '/redis.conf', '(?:bind\\s+127\\.0\\.0\\.1|requirepass\\s+)', 'high'],
  ['rabbitmq-config', '/rabbitmq.conf', '(?:listeners\\.tcp\\.|management\\.tcp\\.)', 'medium'],
  ['postgres-hba', '/pg_hba.conf', '^(?:local|host)\\s+\\w+\\s+', 'high'],
  ['mysql-config', '/my.cnf', '^\\[mysqld\\]', 'medium']
]

const SUFFIXES = ['.bak', '.old', '.orig', '.save', '.backup', '~'] as const

export const MODERN_BACKUP_RULES: Template[] = SOURCES.flatMap(([id, path, marker, severity]) =>
  SUFFIXES.map((suffix, n): Template => ({
    id: `modern-backup-${id}-${n + 1}`,
    kind: 'http-active', confidence: 'confirmed', group: `modern-backup-${id}`,
    request: { method: 'GET', path: path + suffix },
    info: {
      name: `Exposed ${path} backup (${suffix})`, severity,
      description: 'A backup copy of this configuration artifact was served publicly. The match is based on file-specific content.',
      remediation: 'Remove backup files from the web root, restrict access, and rotate any credentials found in the exposed copy.',
      reference: ['https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/01-Information_Gathering/04-Review_Webserver_Metafiles_for_Information_Leakage/'],
      classification: { cwe: ['CWE-538'] }, tags: ['exposure', 'backup', 'configuration', '2025-pack']
    },
    matchers: [{ type: 'status', status: [200] }, { type: 'regex', part: 'body', regex: [marker] }]
  }))
)
