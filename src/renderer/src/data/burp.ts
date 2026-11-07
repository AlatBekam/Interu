// Payload sets offered by the Intruder. Plain wordlists, nothing is sent from here.
export const PAYLOAD_SETS: Record<string, string[]> = {
  'Common usernames': ['admin', 'administrator', 'root', 'demo', 'test', 'guest', 'operator', 'svc_backup'],
  'SQLi probes': ["'", "' OR '1'='1", "'--", '" OR 1=1--', '1; DROP TABLE users', "' UNION SELECT NULL--"],
  'Directory fuzz': ['/admin', '/.env', '/backup.zip', '/config.php', '/.git/HEAD', '/api/v1', '/debug', '/server-status'],
  'HTTP methods': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'PATCH']
}
