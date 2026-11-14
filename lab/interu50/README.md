# Interu 150 local lab

This deliberately vulnerable lab serves **150 training cases** with flags from `RUY{harusnya_kamu_gabisa_liat_ini1}` through `RUY{harusnya_kamu_gabisa_liat_ini150}`. Cases 1–50 are distinct public backup exposures. Cases 51–150 cover ten cases each of SQL injection, XSS, LFI, SSTI, command injection, SSRF, XXE, IDOR, CSRF, and debug trace exposure. The contents are synthetic and contain no real credentials.

The Compose service binds only to `127.0.0.1:3000`, runs as an unprivileged user, uses a read-only filesystem and drops Linux capabilities. It does not alter the earlier `lab-interu` container.

## Run

From the repository root:

```powershell
& 'C:\Users\rangk\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe' compose -f lab/interu50/compose.yaml up -d --build
```

Landing page: `http://127.0.0.1:3000/`. Health endpoint: `http://127.0.0.1:3000/health`.

In Interu, add `localhost` to **Authorized scope** and set the target to `http://localhost:3000/` in Active Scan, Rule Engine, or Pentest Automation. For the automated live test, add `127.0.0.1` to scope and run:

```powershell
$env:INTERU50_LIVE='1'
npm test -- --reporter=dot testcase/interu50-live.test.ts
```

Stop the lab with:

```powershell
& 'C:\Users\rangk\AppData\Local\Programs\DockerDesktop\resources\bin\docker.exe' compose -f lab/interu50/compose.yaml down
```

Interu's lab rules match response status and behavior markers; the expected flag text is not embedded in these rules. The original backup rules match file-specific content markers. A plain 200 response or flag alone does not satisfy the matcher. These rules run for any authorized target, so an identical online deployment can return the same results. This lab checks functional integration only; it does not measure scanner accuracy on independent targets or prove 150 independent vulnerability classes.
