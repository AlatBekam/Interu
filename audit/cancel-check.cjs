const fs = require('node:fs');
const ts = require('typescript');
const net = require('node:net');
require.extensions['.ts'] = (mod, filename) => mod._compile(ts.transpileModule(fs.readFileSync(filename,'utf8'), {compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022,esModuleInterop:true}}).outputText,filename);
const {runScan,cancelScan} = require('../src/main/scan.ts');
(async()=>{
 const sockets=new Set(); let connections=0;
 const server=net.createServer(socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));connections++; if(connections===2)setTimeout(()=>cancelScan(4242),30);});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 const port=server.address().port;
 const task=runScan({scanId:4242,target:'127.0.0.1',profile:'deep',ips:['127.0.0.1'],ports:[port],grabBanner:true,timeoutMs:200,concurrency:1},()=>{}).then(()=> 'resolved');
 const result=await Promise.race([task,new Promise(resolve=>setTimeout(()=>resolve('still_pending_after_1000ms'),1000))]);
 for(const socket of sockets)socket.destroy();
 await new Promise(resolve=>server.close(resolve));
 const output={test:'cancel during banner read on self-created loopback listener',connections,result};
 fs.writeFileSync('audit/cancel-check-result.json',JSON.stringify(output,null,2));
 console.log(JSON.stringify(output,null,2));
})().catch(e=>{console.error(e);process.exitCode=1;});
