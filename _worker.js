const textEncoder = new TextEncoder();
const validSecret = value => /^[a-f0-9]{64}$/i.test(value || '');
const nowSeconds = () => Math.floor(Date.now()/1000);
const noCache = {'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff'};
const reply = (data,status=200) => new Response(JSON.stringify(data),{status,headers:{...noCache,'Content-Type':'application/json'}});
const same = (a,b) => {if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length)return false;let different=0;for(let i=0;i<a.length;i++)different|=a.charCodeAt(i)^b.charCodeAt(i);return different===0;};
const bearer = request => request.headers.get('Authorization')?.replace(/^Bearer /,'') || '';
const random = () => Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
async function sha(value){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',textEncoder.encode(value))),b=>b.toString(16).padStart(2,'0')).join('');}
function base64(bytes){let s='';for(let i=0;i<bytes.length;i+=32768)s+=String.fromCharCode(...bytes.subarray(i,i+32768));return btoa(s).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');}
function unbase64(value){if(!/^[\w-]+$/.test(value))throw Error('BAD_CIPHER');return Uint8Array.from(atob(value.replaceAll('-','+').replaceAll('_','/')),c=>c.charCodeAt(0));}
async function encryptionKey(secret,context){const bytes=await crypto.subtle.digest('SHA-256',textEncoder.encode(context+':'+secret));return crypto.subtle.importKey('raw',bytes,'AES-GCM',false,['encrypt','decrypt']);}
async function seal(secret,value,context,compress=false){
  let bytes=textEncoder.encode(JSON.stringify(value));
  if(compress)bytes=new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(new CompressionStream('gzip'))).arrayBuffer());
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const encrypted=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:textEncoder.encode(context)},await encryptionKey(secret,context),bytes));
  return base64(iv)+'.'+base64(encrypted);
}
async function unseal(secret,cipher,context,compress=false){
  const parts=cipher.split('.');if(parts.length!==2)throw Error('BAD_CIPHER');
  let bytes=await crypto.subtle.decrypt({name:'AES-GCM',iv:unbase64(parts[0]),additionalData:textEncoder.encode(context)},await encryptionKey(secret,context),unbase64(parts[1]));
  if(compress)bytes=await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
  return JSON.parse(new TextDecoder().decode(bytes));
}

export default {async fetch(request,env){
 const url=new URL(request.url);
 if(url.pathname!=='/api/owner-recovery/config')return env.ASSETS.fetch(request);
 const deny=(code,status)=>new Response(JSON.stringify({ok:false,code}),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store'}});
 const credential=request.headers.get('Authorization')?.replace(/^Bearer /,'')||'';
 if(request.method!=='POST'||request.headers.has('Origin')||!env.MIGRATION_ADMIN_TOKEN||credential!==env.MIGRATION_ADMIN_TOKEN)return deny('UNAUTHORIZED',401);
 try{
  const row=await env.AJJAN_DB.prepare('SELECT cipher FROM ajjan_service_config WHERE id=1').first();
  if(!row)return deny('NO_BACKUP',404);
  const backup=await unseal(env.KEY_CONFIG_SECRET,row.cipher,'ajjan-main-configuration-v1',true);
  const cipher=await seal(env.MIGRATION_ADMIN_TOKEN,backup,'ajjan-owner-recovery-export-v1',true);
  return new Response(JSON.stringify({ok:true,cipher}),{headers:{'Content-Type':'application/json','Cache-Control':'no-store','Referrer-Policy':'no-referrer'}});
 }catch{return deny('BACKUP_UNAVAILABLE',503);}
}};
