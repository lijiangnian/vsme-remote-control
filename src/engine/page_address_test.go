package main

import (
	"os/exec"
	"strings"
	"testing"
)

// Exercise the shared Mac page handlers with a minimal DOM. This is not a
// substitute for real Safari / macOS permission and clipboard verification.
func TestMacPageDualStatusAndClipboardFallback(t *testing.T) {
	start := strings.Index(page, "<script>") + len("<script>")
	end := strings.Index(page, "</script>")
	stub := `
const assert=require('node:assert/strict');
const nodes={};
function element(){return {textContent:'',value:'',style:{},dataset:{},append(){},replaceChildren(){},after(){},focus(){this.focused=true}}}
global.document={getElementById(id){return nodes[id]||(nodes[id]=element())},createElement:element,querySelectorAll(){return []}};
global.location={hash:'#local-test',pathname:'/'};global.history={replaceState(){}};global.window={addEventListener(){}};global.setInterval=()=>{};
let snapshot={role:'agent',machine:{name:'Mac-test',user:'test',os:'darwin',ips:['192.168.1.51']},connections:[{name:'CONTROL-A',state:'connected',controller:'https://10.77.0.11:45842'},{name:'CONTROL-B',state:'discovering',controller:'https://10.77.0.12:45842'}]};
let clipboardError=true,reads=0,imports=[],failStatus=false;
Object.defineProperty(global,'navigator',{value:{clipboard:{async readText(){reads++;if(clipboardError)throw Error('clipboard denied');return 'CHAT\nVSME-ADDRESS2:test\nwhole message'}}},configurable:true});
global.fetch=async(path,options)=>{const data=JSON.parse(options.body);if(path==='/api/status'){if(failStatus)throw Error('offline');return {ok:true,json:async()=>snapshot}}if(path==='/api/import-controller-address'){imports.push(data.invite);return {ok:true,json:async()=>({controller:'CONTROL-B,CONTROL-A',address:'10.77.0.14,10.77.0.11'})}}return {ok:true,json:async()=>({})}};
`
	checks := `
setImmediate(async()=>{try{
 assert.equal(reads,0,'must not read clipboard before user clicks');
 assert.match(nodes.state.textContent,/1\/2/);assert.equal(nodes.state.style.color,'#ffd074');
 await nodes.pasteAddress.onclick();assert.equal(imports.length,0);assert.equal(nodes.sharedAddress.focused,true);assert.match(nodes.importStatus.textContent,/Command\+V/);assert.equal(nodes.pasteAddress.disabled,false);
 clipboardError=false;await nodes.pasteAddress.onclick();assert.deepEqual(imports,['CHAT\nVSME-ADDRESS2:test\nwhole message']);
 snapshot.connections[1].state='connected';await refresh();assert.match(nodes.state.textContent,/2\/2/);assert.equal(nodes.state.style.color,'#4fe0ac');
 snapshot.connections[0].state='disconnected';await refresh();assert.match(nodes.state.textContent,/1\/2/);assert.equal(nodes.state.style.color,'#ffd074');
 failStatus=true;await refresh();assert.match(nodes.state.textContent,/无法确认/);assert.equal(nodes.state.style.color,'#ffd074');
 failStatus=false;snapshot.role='controller';snapshot.machine.name='CONTROL-B';snapshot.connections=[{name:'CONTROL-A',state:'connected'}];snapshot.peers=[];await refresh();assert.match(nodes.state.textContent,/未齐/);
 snapshot.peers=[{id:'peer',revoked:false,machine:{name:'CONTROL-A',ips:[],os:'windows'},jobs:[]}];await refresh();assert.match(nodes.state.textContent,/双向连接已就绪/);
 console.log('MAC_PAGE_DUAL_STATUS_CLIPBOARD_FALLBACK=PASS');
}catch(e){console.error(e);process.exitCode=1}});
`
	cmd := exec.Command("node")
	cmd.Stdin = strings.NewReader(stub + page[start:end] + checks)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}
