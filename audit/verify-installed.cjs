const fs = require('node:fs');
const path = require('node:path');
const { _electron } = require('playwright-core');
(async () => {
  const env = { ...process.env };
  delete env.ELECTRON_RUN_AS_NODE;
  delete env.RUY_SMOKE_TEST;
  const application = await _electron.launch({ executablePath: 'C:\\Users\\rangk\\AppData\\Local\\Programs\\Interu\\Interu.exe', env, timeout: 30000 });
  try {
    const page = await application.firstWindow();
    await application.evaluate(({ BrowserWindow }) => { for (const w of BrowserWindow.getAllWindows()) w.hide(); });
    await page.getByText('Exposure Monitor', {exact:true}).first().waitFor({timeout:30000});
    const result = await application.evaluate(({ app }) => ({ version:app.getVersion(), appPath:app.getAppPath(), userData:app.getPath('userData') }));
    result.renderer = await page.evaluate(() => ({ title:document.title, bridgeHttp:typeof window.ruy?.http?.send==='function', bridgeScan:typeof window.ruy?.scan?.run==='function', bridgeAutomation:typeof window.ruy?.automation?.start==='function', hasExposureMonitor:document.body.innerText.includes('Exposure Monitor'), settingsStored:localStorage.getItem('ruy.v1.settings')!==null, findingsStored:localStorage.getItem('ruy.v1.findings')!==null }));
    await page.getByText('Pentest Automation', {exact:true}).first().click();
    await page.getByText('OWASP Top 10:2025 coverage', {exact:true}).waitFor({timeout:10000});
    result.renderer.automationScreen = true;
    result.renderer.top10Categories = await page.locator('table.data tbody tr').count();
    await page.screenshot({path:path.join(__dirname,'installed-app.png')});
    fs.writeFileSync(path.join(__dirname,'installed-verification.json'),JSON.stringify(result,null,2));
    console.log(JSON.stringify(result,null,2));
  } finally { await application.close(); }
})().catch(err => { console.error(err); process.exitCode=1; });
