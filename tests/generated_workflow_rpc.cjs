// Execute generated graph nodes, delegating HTTP to Python Flask test clients over stdio.
// No network APIs, engine, credentials, Docker, or existing databases are accessed.
const fs = require('node:fs');
const spec = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const workflows = Object.fromEntries(Object.values(spec.workflows).map(w => [w.id, w]));
function rpc(request) {
 process.stdout.write(JSON.stringify({type:'http',...request})+'\n');
 let line='', byte=Buffer.alloc(1);
 while(fs.readSync(0,byte,0,1,null)) {if(byte[0]===10)break;line+=byte.toString('utf8');}
 if(!line)throw Error('Flask transport closed');
 return JSON.parse(line);
}
function run(id,input,execution) {
 const w=workflows[id],nodes=Object.fromEntries(w.nodes.map(n=>[n.name,n])),outputs={};
 const selector=name=>({first:()=>({json:outputs[name]})});
 const expr=(v,j)=>typeof v==='string' && v.startsWith('={{')?
   new Function('$json','$',`return (${v.slice(3,-2)});`)(j,selector):v;
 let name=w.nodes.find(n=>/\.(webhook|executeWorkflowTrigger)$/.test(n.type)).name,j=input;
 for(let budget=0;budget<500;budget++) {
  const n=nodes[name],p=n.parameters,kind=n.type.split('.').pop();let branch=0;
  if(kind==='code')j=new Function('$input','$execution','$','$getWorkflowStaticData',p.jsCode)(
    {first:()=>({json:j}),all:()=>[{json:j}]},{id:execution},selector,()=>{throw Error('Static-store fallback forbidden');})[0].json;
  else if(kind==='if')branch=expr(p.conditions.conditions[0].leftValue,j)===true?0:1;
  else if(kind==='executeWorkflow')j=run(p.workflowId.value,j,execution);
  else if(kind==='httpRequest') {
   const headers=Object.fromEntries((p.headerParameters?.parameters||[]).map(v=>[v.name,expr(v.value,j)]));
   const body=expr(p.sendBody,j)===false?null:p.jsonBody?JSON.parse(expr(p.jsonBody,j)):
     Object.fromEntries((p.bodyParameters?.parameters||[]).map(v=>[v.name,expr(v.value,j)]));
   j=rpc({method:expr(p.method,j),url:expr(p.url,j),headers,body,credential:n.credentials?.httpHeaderAuth?.id});
  } else if(kind==='respondToWebhook')return {...j,actual_response_code:expr(p.options.responseCode,j)};
  else if(!['webhook','executeWorkflowTrigger'].includes(kind))throw Error('Unsupported node '+kind);
  outputs[name]=JSON.parse(JSON.stringify(j));
  const edges=w.connections[name]?.main[branch]||[];
  if(!edges.length)return j;
  if(edges.length!==1)throw Error('Unexpected fanout');
  name=edges[0].node;
 }
 throw Error('Graph did not terminate');
}
const results=spec.requests.map((request,i)=>run(request.workflow,{body:request.body},'rpc-'+(i+1)));
process.stdout.write(JSON.stringify({type:'result',results})+'\n');
