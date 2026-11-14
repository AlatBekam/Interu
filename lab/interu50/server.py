"""Intentionally exposed configuration backups for an isolated Interu training lab."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html import escape
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import traceback
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import urlopen
from xml.parsers import expat

# Every entry is a separately reachable backup configuration file. These are
# inert training fixtures, not real keys. The flag is separate from the marker
# so the scanner must first identify the exposed file by its actual contents.
FILES = [
    ("/config/secrets.yml.bak", "secret_key_base: training_only"),
    ("/config/initializers/devise.rb.bak", "Devise.setup do |config|\n  config.mailer_sender = 'lab@example.invalid'\nend"),
    ("/config/mongoid.yml.bak", "development:\n  hosts:\n    - localhost:27017"),
    ("/config/redis.yml.bak", "redis:\n  host: localhost"),
    ("/config/cable.yml.bak", "adapter: redis"),
    ("/config/storage.yml.bak", "service: Disk"),
    ("/config/sidekiq.yml.bak", ":concurrency: 5"),
    ("/config/schedule.rb.bak", "every 1.day do\n  rake 'lab:noop'\nend"),
    ("/config/webpacker.yml.bak", "source_path: app/javascript"),
    ("/config/puma.rb.bak", "workers 2"),
    ("/settings_local.py.bak", "SECRET_KEY = 'training-only'"),
    ("/project/settings/production.py.bak", "DATABASES = {'default': {}}"),
    ("/instance/config.py.bak", "SQLALCHEMY_DATABASE_URI = 'sqlite:///lab.db'"),
    ("/config/auth.php.bak", "<?php return ['defaults' => ['guard' => 'web']];"),
    ("/config/database.php.bak", "<?php return ['connections' => ['sqlite' => []]];"),
    ("/config/mail.php.bak", "<?php return ['mailers' => ['log' => []]];"),
    ("/config/filesystems.php.bak", "<?php return ['disks' => ['local' => []]];"),
    ("/config/services.yaml.bak", "services:\n  _defaults: {}"),
    ("/config/packages/security.yaml.bak", "security:\n  providers: {}"),
    ("/appsettings.Production.json.bak", '{"ConnectionStrings":{"Default":"training-only"}}'),
    ("/.npmrc.bak", "registry=https://registry.npmjs.org/"),
    ("/.pypirc.bak", "[distutils]\nindex-servers = pypi"),
    ("/.m2/settings.xml.bak", "<settings><servers></servers></settings>"),
    ("/gradle.properties.bak", "org.gradle.jvmargs=-Xmx512m"),
    ("/docker-compose.yml.bak", "services:\n  app:\n    image: training-only"),
    ("/compose.prod.yaml.bak", "services:\n  app:\n    image: training-only"),
    ("/helm/values.yaml.bak", "replicaCount: 1\nimage:\n  repository: training-only"),
    ("/charts/app/Chart.yaml.bak", "apiVersion: v2\nname: training-only"),
    ("/kustomization.yaml.bak", "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization"),
    ("/terraform.tfvars.bak", 'region = "us-east-1"'),
    ("/backend.tf.bak", 'terraform {\n backend "local" {}\n}'),
    ("/terragrunt.hcl.bak", "terraform {\n source = './module'\n}"),
    ("/packer.json.bak", '{"builders":[{"type":"null"}]}'),
    ("/inventory.ini.bak", "[webservers]\nlab ansible_host=127.0.0.1"),
    ("/group_vars/all.yml.bak", "ansible_user: lab"),
    ("/.github/workflows/deploy.yml.bak", "jobs:\n  deploy:\n    runs-on: ubuntu-latest"),
    ("/.gitlab-ci.yml.bak", "stages:\n  - test\nimage: alpine"),
    ("/.buildkite/pipeline.yml.bak", "steps:\n  - command: echo training-only"),
    ("/argocd/application.yaml.bak", "apiVersion: argoproj.io/v1alpha1\nkind: Application"),
    ("/skaffold.yaml.bak", "apiVersion: skaffold/v4beta1"),
    ("/k8s/secret.yaml.bak", "apiVersion: v1\nkind: Secret\ndata: {}"),
    ("/k8s/deployment.yaml.bak", "apiVersion: apps/v1\nkind: Deployment"),
    ("/prometheus.yml.bak", "scrape_configs:\n  - job_name: lab"),
    ("/provisioning/datasources/default.yaml.bak", "datasources:\n  - name: lab"),
    ("/nginx.conf.bak", "http {\n server { listen 80; }\n}"),
    ("/sites-available/000-default.conf.bak", "<VirtualHost *:80>\n ServerName lab.invalid\n</VirtualHost>"),
    ("/redis.conf.bak", "bind 127.0.0.1\nrequirepass training-only"),
    ("/rabbitmq.conf.bak", "listeners.tcp.default = 5672"),
    ("/pg_hba.conf.bak", "host all all 127.0.0.1/32 scram-sha-256"),
    ("/my.cnf.bak", "[mysqld]\nbind-address=127.0.0.1"),
]

assert len(FILES) == 50 and len({path for path, _ in FILES}) == 50
PAGES = {
    path: (body + f"\n# lab_flag RUY{{harusnya_kamu_gabisa_liat_ini{number}}}\n").encode()
    for number, (path, body) in enumerate(FILES, 1)
}
HOME = Path(__file__).with_name("index.html").read_bytes()
KINDS = ("sqli", "xss", "lfi", "ssti", "rce", "ssrf", "xxe", "idor", "csrf", "debug")
PREFIXES = ("api/search", "search", "docs", "render", "tools", "fetch", "xml", "records", "forms", "debug")
CASE_ROUTE = re.compile(r"^/([a-z]+(?:/[a-z]+)?)/(10|[1-9])$")
COUNTS = {n: 0 for n in range(1, 11)}


def case_number(kind, n):
    return 51 + KINDS.index(kind) * 10 + n - 1


def training_flag(kind, n):
    return f"RUY{{harusnya_kamu_gabisa_liat_ini{case_number(kind, n)}}}"


def case_list():
    sample = {
        "sqli": {"id": "1"}, "xss": {"q": "hello"}, "lfi": {"file": "welcome.txt"},
        "ssti": {"template": "Welcome"}, "rce": {"cmd": "status"},
        "ssrf": {"url": "http://127.0.0.1:1/"},
        "xxe": {"data": "<r>hello</r>"}, "idor": {"user": "1"}, "csrf": {}, "debug": {}
    }
    items = []
    for kind, prefix in zip(KINDS, PREFIXES):
        links = "".join(
            f'<a href="/{prefix}/{n}{"?" + urlencode(sample[kind]) if sample[kind] else ""}">Case {n:02d}</a>'
            for n in range(1, 11)
        )
        items.append(f"<section><h2>{kind.upper()}</h2><div>{links}</div></section>")
    return ("<!doctype html><html lang='id'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>RUY Training Modules</title><style>body{background:#081522;color:#edf5fa;font:16px system-ui;margin:0;padding:30px;max-width:1100px}"
            "a{color:#75e0d1}h1{font-size:36px}section{border:1px solid #264353;background:#102635;border-radius:12px;padding:20px;margin:16px 0}"
            "section div{display:flex;gap:15px;flex-wrap:wrap}section a{padding:8px 13px;border:1px solid #3d6b75;border-radius:6px;text-decoration:none}</style>"
            "<a href='/'>← Beranda</a><h1>RUY Training Modules</h1><p>100 kasus tambahan dalam 10 kategori. Gunakan hanya di localhost.</p>"
            + "".join(items) + "</html>").encode()


def xml_with_external_entities(text):
    output = []
    parser = expat.ParserCreate()
    parser.CharacterDataHandler = output.append

    def resolve(context, base, system_id, public_id):
        if system_id != "file:///etc/passwd":
            return 0
        child = parser.ExternalEntityParserCreate(context)
        child.CharacterDataHandler = output.append
        with open("/etc/passwd", "rb") as local_file:
            child.Parse(local_file.read(), True)
        return 1

    parser.ExternalEntityRefHandler = resolve
    parser.Parse(text, True)
    return "".join(output)


def case_response(kind, n, params):
    value = lambda key, default="": params.get(key, [default])[0][:512]
    status, mime, body, exposed = 200, "text/plain; charset=utf-8", "", False
    if kind == "sqli":
        db = sqlite3.connect(":memory:")
        try:
            db.execute("CREATE TABLE inventory(id INTEGER, label TEXT)")
            db.execute("INSERT INTO inventory VALUES (1, 'Training item')")
            # Deliberately unsafe interpolation for the local SQLi lab.
            row = db.execute("SELECT label FROM inventory WHERE id = " + value("id", "1")).fetchone()
            body = row[0] if row else "No result"
        except sqlite3.OperationalError as error:
            status, body, exposed = 500, f"sqlite3.OperationalError: {error}", True
        finally:
            db.close()
    elif kind == "xss":
        q = value("q")
        mime, body, exposed = "text/html; charset=utf-8", f"<h1>Search results</h1><p>Query: {q}</p>", "<" in q
    elif kind == "lfi":
        try:
            with open("/app/" + value("file", "welcome.txt"), "r", encoding="utf-8") as local_file:
                body = local_file.read(4096)
            exposed = "root:" in body
        except OSError:
            status, body = 404, "File not found"
    elif kind == "ssti":
        raw = value("template")
        expression = re.search(r"\{\{(.+?)\}\}", raw)
        try:
            body = "Rendered: " + (str(eval(expression.group(1), {"__builtins__": {}}, {})) if expression else raw)
            exposed = expression is not None
        except Exception as error:
            status, body = 500, f"Template error: {error}"
    elif kind == "rce":
        cmd = value("cmd", "status")
        try:
            result = subprocess.run("echo " + cmd, shell=True, text=True, capture_output=True, timeout=1, check=False)
            body, exposed = result.stdout[:4096], "interu_" in result.stdout
        except Exception as error:
            status, body = 500, f"Command error: {error}"
    elif kind == "ssrf":
        target = value("url")
        if urlsplit(target).hostname != "127.0.0.1":
            status, body = 400, "Only the loopback training destination is enabled"
        else:
            try:
                with urlopen(target, timeout=0.4) as response:
                    body = response.read(4096).decode("utf-8", "replace")
            except Exception as error:
                status, body, exposed = 502, str(error), "Connection refused" in str(error)
    elif kind == "xxe":
        try:
            body = xml_with_external_entities(value("data", "<r>hello</r>"))[:4096]
            exposed = "root:" in body
        except Exception as error:
            status, body = 400, f"XML error: {error}"
    elif kind == "idor":
        account = value("user", "1")
        body = f"Account {account} / case {n}\n" + ("Private profile data for another account. " * 5 if account == "2" else "Own profile. ")
        exposed = account == "2"
    elif kind == "csrf":
        mime = "text/html; charset=utf-8"
        body = f'<h1>Transfer approval</h1><form method="POST" action="/forms/{n}/transfer"><input name="amount" value="1"><button>Send</button></form>'
        exposed = True
    elif kind == "debug":
        try:
            raise ValueError(f"Deliberate debug exception, case {n}")
        except ValueError:
            status, body, exposed = 500, traceback.format_exc(), True
    if exposed:
        body += f"\n<!-- lab_flag {training_flag(kind, n)} -->\n" if mime.startswith("text/html") else f"\n# lab_flag {training_flag(kind, n)}\n"
    return status, mime, body.encode()


class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self._serve(False)

    def do_GET(self):
        self._serve(True)

    def do_POST(self):
        match = re.fullmatch(r"/forms/(10|[1-9])/transfer", self.path)
        if not match:
            self.send_error(404)
            return
        n = int(match.group(1))
        COUNTS[n] += 1  # Deliberately no CSRF token or Origin validation.
        body = f"Transfer accepted for case {n}; total {COUNTS[n]}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve(self, include_body):
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/health":
            status, kind, body = 200, "application/json", json.dumps({"status": "ok", "cases": len(PAGES) + 100}).encode()
        elif path == "/":
            status, kind, body = 200, "text/html; charset=utf-8", HOME
        elif path == "/cases":
            status, kind, body = 200, "text/html; charset=utf-8", case_list()
        elif path in PAGES:
            status, kind, body = 200, "text/plain; charset=utf-8", PAGES[path]
        elif (match := CASE_ROUTE.fullmatch(path)) and match.group(1) in PREFIXES:
            kind_name = KINDS[PREFIXES.index(match.group(1))]
            status, kind, body = case_response(kind_name, int(match.group(2)), parse_qs(parsed.query, keep_blank_values=True))
        else:
            status, kind, body = 404, "text/plain; charset=utf-8", b"Not found"
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if include_body:
            self.wfile.write(body)


if __name__ == "__main__":
    print("Interu training lab listening on 0.0.0.0:3000", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 3000), Handler).serve_forever()
