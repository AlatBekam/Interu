// Local-only review probes; no network traffic or application data access.
const fs = require('node:fs');
const path = require('node:path');
const ts = require('typescript');
require.extensions['.ts'] = (mod, filename) => {
  const source = fs.readFileSync(filename, 'utf8');
  mod._compile(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true } }).outputText, filename);
};
const rules = require('../src/shared/rules.ts');
const web = require('../src/shared/webvuln.ts');
const auth = require('../src/shared/auth.ts');
const scan = require('../src/shared/scan.ts');
const tokens = require('../src/shared/tokens.ts');
const kev = require('../src/shared/kev.ts');
const entry = (headers, body = '<html>ordinary page</html>') => ({ id: 1, time: '', method: 'GET', host: 'review.invalid', path: '/', url: 'https://review.invalid/', status: 200, length: body.length, ms: 1, kind: 'http', response: `HTTP/1.1 200 OK\r\n${headers}\r\n\r\n${body}` });
const cookieFindings = rules.analyzeHttpResponse(entry('Content-Type: text/html\r\nSet-Cookie: sid=FAKE_REVIEW_SECRET'));
const cors = rules.analyzeHttpResponse(entry('Content-Type: text/html\r\nAccess-Control-Allow-Origin: https://trusted.invalid\r\nAccess-Control-Allow-Credentials: true'));
const t = rules.TEMPLATES.find(t => t.id === 'expose-git-config');
const baseline = rules.computeBaseline({ok:true,status:200,body:'<html>repositoryformatversion documentation</html>',timingMs:1,size:50});
const soft404 = rules.matchActive(t,'https://review.invalid/.git/config',{ok:true,status:200,body:'<html>repositoryformatversion documentation</html>',timingMs:1,size:50},{baseline});
const standard = new Set(scan.profilePorts('standard'));
const result = {
  templateCounts: rules.TEMPLATES.reduce((a,t)=>(a[t.kind]=(a[t.kind]||0)+1,a), {total: rules.TEMPLATES.length}),
  backupVariantCount: rules.TEMPLATES.filter(t=>t.id.startsWith('bak-')).length,
  kevSnapshot: {version:kev.KEV_CATALOG_VERSION,count:kev.KEV_COUNT},
  ports: {quick:scan.profilePorts('quick').length,standard:standard.size,missingCommonPorts:[2375,2376,2379,2380,6379,6443,10250,11211,27017].filter(p=>!standard.has(p))},
  xssCommentOnly: web.xssReflectVerdict('<!-- <x-interu-review123> -->','review123','text/html'),
  sqliErrorPersistsWhenBalanced: web.sqliErrorVerdict('ordinary page','SQL syntax error MySQL','SQL syntax error MySQL'),
  allowedFixedOriginCors: cors.filter(f=>f.templateId==='http-cors-credentials-wildcard').map(f=>({name:f.name,confidence:f.confidence})),
  evidenceRedactedButRawResponseContainsSecret: cookieFindings.filter(f=>f.templateId==='http-cookie-httponly').map(f=>({evidence:f.evidence,responseContainsFakeSecret:f.response.includes('FAKE_REVIEW_SECRET')})),
  multipleCookiesRedaction: auth.redactSecrets('Cookie: first=FAKE_ONE; second=FAKE_TWO'),
  catchAllWithSameMarker: soft404 && {confidence:soft404.confidence,evidence:soft404.evidence},
  networkFailureMatch: rules.matchActive(t,'https://review.invalid/.git/config',{ok:false,error:'timeout',timingMs:1,size:0}),
  deterministicTokens: tokens.analyzeTokens(['0123456789','1234567890','2345678901','3456789012']),
  repeatedTokenSample: tokens.parseTokens('same\nsame\nsame\nother').length
};
console.log(JSON.stringify(result,null,2));
fs.writeFileSync(path.join(__dirname,'review-checks-result.json'),JSON.stringify(result,null,2)+'\n');
