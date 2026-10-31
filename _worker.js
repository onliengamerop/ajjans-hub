const HEX=/^[a-f0-9]{64}$/i;
const KEY=/^(?:[a-f0-9]{32}|AJJANS-(?:[A-Z0-9]{4}-){2}[A-Z0-9]{4})$/i;
const canonical=key=>/^[a-f0-9]{32}$/i.test(key)?key.toLowerCase():key.toUpperCase();
const statusSQL="CASE WHEN deleted_at IS NOT NULL THEN 'deleted' WHEN revoked=1 THEN 'banned' WHEN expires_at IS NOT NULL AND expires_at<=? THEN 'expired' ELSE 'active' END";

function expiry(body,now) {
  if(body.lifetime===true)return null;
  if(body.expires_at!==undefined){if(!Number.isInteger(body.expires_at)||body.expires_at<0||body.expires_at>now+315360000)throw new Error('INVALID_EXPIRY');return body.expires_at;}
  if(body.duration!==undefined){const units={minutes:60,hours:3600,days:86400,weeks:604800},unit=units[body.unit];if(!unit||!Number.isInteger(body.duration)||body.duration<1||body.duration*unit>315360000)throw new Error('INVALID_EXPIRY');return now+body.duration*unit;}
  const hours=body.hours??15;if(!Number.isInteger(hours)||hours<1||hours>87600)throw new Error('INVALID_EXPIRY');return now+hours*3600;
}
const cleanNote=value=>{if(typeof value!=='string'||value.length>200)throw new Error('INVALID_NOTE');return value.trim();};

async function handleAdmin(request,env,ctx,h) {
  const {path,now,json,fail,readJSON,digest,deriveKey,displayKey,equalSecret,randomHex,rateLimit,cleanupExpiredKeys,decryptDeviceID,expiredKeyRetention}=h;
  const bearer=request.headers.get('Authorization')?.replace(/^Bearer /,'')||'';
  const panel=HEX.test(env.ADMIN_PANEL_TOKEN||'')&&equalSecret(bearer,env.ADMIN_PANEL_TOKEN);
  if(!panel&&!(HEX.test(env.ADMIN_TOKEN||'')&&equalSecret(bearer,env.ADMIN_TOKEN)))return fail('UNAUTHORIZED',401);
  const forwarded=request.headers.get('X-Ajjan-Panel-Client-IP')||'';
  const ratedRequest=panel&&/^[a-f0-9.:]{3,64}$/i.test(forwarded)?{headers:new Headers({'CF-Connecting-IP':forwarded})}:request;
  if(!await rateLimit(env,ratedRequest,'admin',180,now,ctx))return fail('RATE_LIMITED',429);
  const body=await readJSON(request), action=path.slice('/api/keys/admin/'.length);
  const audit=(action,keyID,detail={})=>env.AJJAN_DB.prepare('INSERT INTO ajjan_admin_audit(at,action,key_id,detail) VALUES(?,?,?,?)').bind(now,action,keyID,JSON.stringify(detail));
  try {
    if(['stats','list'].includes(action))await cleanupExpiredKeys(env,now);
    if(action==='panel-login'){
      if(!panel)return fail('UNAUTHORIZED',401);
      if(!await rateLimit(env,ratedRequest,'panel-login',6,now,ctx))return fail('RATE_LIMITED',429);
      if(body.authenticated!==true)return fail('UNAUTHORIZED',401,'Invalid admin access key.');
      if(!HEX.test(body.token_hash||''))return fail('INVALID_REQUEST');
      await env.AJJAN_DB.batch([
        env.AJJAN_DB.prepare('DELETE FROM ajjan_admin_sessions WHERE expires_at<=?').bind(now),
        env.AJJAN_DB.prepare('INSERT INTO ajjan_admin_sessions(token_hash,credential_hash,created_at,expires_at) VALUES(?,?,?,?)').bind(body.token_hash,await digest(env.ADMIN_PANEL_TOKEN),now,now+7200),
        audit('sign-in',null),
      ]);
      return json({ok:true,expires_at:now+7200});
    }
    if(action==='panel-session'){
      if(!panel||!HEX.test(body.token_hash||''))return fail('UNAUTHORIZED',401);
      const session=await env.AJJAN_DB.prepare('SELECT expires_at FROM ajjan_admin_sessions WHERE token_hash=? AND credential_hash=? AND expires_at>?').bind(body.token_hash,await digest(env.ADMIN_PANEL_TOKEN),now).first();
      return session?json({ok:true,expires_at:session.expires_at}):fail('UNAUTHORIZED',401);
    }
    if(action==='panel-logout'){
      if(!panel||!HEX.test(body.token_hash||''))return fail('UNAUTHORIZED',401);
      await env.AJJAN_DB.prepare('DELETE FROM ajjan_admin_sessions WHERE token_hash=?').bind(body.token_hash).run();
      return json({ok:true});
    }
    if(action==='stats'){
      const stats=await env.AJJAN_DB.prepare(`SELECT COUNT(*) AS total,
        SUM(CASE WHEN deleted_at IS NULL AND revoked=0 AND (expires_at IS NULL OR expires_at>?) THEN 1 ELSE 0 END) AS active,
        SUM(CASE WHEN deleted_at IS NULL AND revoked=1 THEN 1 ELSE 0 END) AS banned,
        SUM(CASE WHEN deleted_at IS NULL AND revoked=0 AND expires_at IS NOT NULL AND expires_at<=? THEN 1 ELSE 0 END) AS expired,
        SUM(CASE WHEN deleted_at IS NULL AND device_hash IS NOT NULL THEN 1 ELSE 0 END) AS hwid_locked,
        SUM(CASE WHEN source='ads' THEN 1 ELSE 0 END) AS ads_keys,
        SUM(CASE WHEN source='manual' THEN 1 ELSE 0 END) AS manual_keys,
        SUM(CASE WHEN deleted_at IS NOT NULL THEN 1 ELSE 0 END) AS deleted,
        COUNT(DISTINCT CASE WHEN source='ads' THEN browser_hash END) AS key_holders FROM ajjan_keys`).bind(now,now).first();
      for(const name of Object.keys(stats))stats[name]=Number(stats[name]||0);
      return json({ok:true,stats});
    }
    if(action==='list'){
      const page=Number.isInteger(body.page)&&body.page>0?Math.min(body.page,100000):1, limit=25;
      const filters=[],args=[];const status=body.status||'all',source=body.source||'all';
      if(status==='deleted')filters.push('deleted_at IS NOT NULL');else filters.push('deleted_at IS NULL');
      if(status==='banned')filters.push('revoked=1');
      if(status==='expired'){filters.push('revoked=0 AND expires_at IS NOT NULL AND expires_at<=?');args.push(now);}
      if(status==='active'){filters.push('revoked=0 AND (expires_at IS NULL OR expires_at>?)');args.push(now);}
      if(['ads','manual'].includes(source)){filters.push('source=?');args.push(source);}
      const search=typeof body.search==='string'?body.search.trim().slice(0,40):'';
      if(search){const hash=KEY.test(search)?await digest(canonical(search)):'';filters.push("(key_hash=? OR legacy_key_hash=? OR note LIKE ? ESCAPE '\\' OR id=?)");args.push(hash,hash,'%'+search.replace(/[\\%_]/g,'\\$&')+'%',search);}
      const where=filters.join(' AND '),count=await env.AJJAN_DB.prepare('SELECT COUNT(*) AS total FROM ajjan_keys WHERE '+where).bind(...args).first();
      const rows=await env.AJJAN_DB.prepare(`SELECT *,${statusSQL} AS status FROM ajjan_keys WHERE ${where} ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?`).bind(now,...args,limit,(page-1)*limit).all();
      const keys=[];
      for(const row of rows.results)keys.push({id:row.id,key:await displayKey(env,row),note:row.note||(row.source==='ads'?'Ads key system':'Admin generated'),source:row.source,status:row.status,hwid_locked:!!row.device_hash,hwid_id:row.device_hash?await decryptDeviceID(env.KEY_SECRET,row.id,row.device_id_ciphertext):null,hwid_fingerprint:row.device_hash||null,delete_at:row.expires_at===null?null:row.expires_at+expiredKeyRetention,created_at:row.created_at,expires_at:row.expires_at,last_used_at:row.last_used_at,executions:row.executions,deleted_at:row.deleted_at});
      return json({ok:true,keys,total:count.total,page,limit});
    }
    if(action==='activity'){
      const rows=await env.AJJAN_DB.prepare('SELECT at,action,key_id,detail FROM ajjan_admin_audit ORDER BY id DESC LIMIT 40').all();
      return json({ok:true,events:rows.results});
    }
    if(action==='provider-events'){
      await env.AJJAN_DB.prepare('CREATE TABLE IF NOT EXISTS ajjan_debug_log (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, step INTEGER, reason TEXT, detail TEXT)').run();
      const provider=['linkvertise','lootlabs'].includes(body.provider)?body.provider:null;
      const query=provider?env.AJJAN_DB.prepare("SELECT at,step,reason,detail FROM ajjan_debug_log WHERE CASE WHEN json_valid(detail) THEN json_extract(detail,'$.provider') END=? ORDER BY id DESC LIMIT 50").bind(provider):env.AJJAN_DB.prepare('SELECT at,step,reason,detail FROM ajjan_debug_log ORDER BY id DESC LIMIT 50');
      return json({ok:true,events:(await query.all()).results});
    }
    if(action==='create'||action==='bulk-create'){
      const count=action==='create'?1:body.count;
      if(!Number.isInteger(count)||count<1||count>100)return fail('INVALID_COUNT',400,'Choose between 1 and 100 keys.');
      const expires=expiry(body,now),note=body.note===undefined?'Admin generated':cleanNote(body.note)||'Admin generated';
      const records=await Promise.all(Array.from({length:count},async()=>{const id=randomHex(16),key=await deriveKey(env.KEY_SECRET,id);return {id,key,hash:await digest(key)};}));
      await env.AJJAN_DB.batch([...records.map(row=>env.AJJAN_DB.prepare("INSERT INTO ajjan_keys(id,key_hash,created_at,expires_at,key_format,source,note) VALUES(?,?,?,?,2,'manual',?)").bind(row.id,row.hash,now,expires,note)),audit(count===1?'create':'bulk-create',count===1?records[0].id:null,{count,note,expires_at:expires})]);
      return json({ok:true,...(count===1?{key:records[0].key,expires_at:expires}:{}),keys:records.map(r=>({id:r.id,key:r.key,note,expires_at:expires,source:'manual'}))});
    }
    if(!['update','revoke','unban','delete','restore','reset-device'].includes(action))return fail('NOT_FOUND',404);
    let row;
    if(typeof body.id==='string'&&/^[a-z0-9_-]{1,128}$/i.test(body.id))row=await env.AJJAN_DB.prepare('SELECT * FROM ajjan_keys WHERE id=?').bind(body.id).first();
    else if(typeof body.key==='string'&&KEY.test(body.key)){const hash=await digest(canonical(body.key));row=await env.AJJAN_DB.prepare('SELECT * FROM ajjan_keys WHERE key_hash=? OR legacy_key_hash=?').bind(hash,hash).first();}
    if(!row)return fail('KEY_INCORRECT',404);
    if(row.deleted_at!==null&&action!=='restore'&&action!=='delete')return fail('KEY_DELETED',409,'Restore this deleted key before changing it.');
    const statements=[],detail={};
    if(action==='update'){
      if(body.note!==undefined){detail.note=cleanNote(body.note);statements.push(env.AJJAN_DB.prepare('UPDATE ajjan_keys SET note=? WHERE id=?').bind(detail.note,row.id));}
      if(body.duration!==undefined||body.expires_at!==undefined||body.lifetime===true){detail.expires_at=expiry(body,now);statements.push(env.AJJAN_DB.prepare('UPDATE ajjan_keys SET expires_at=? WHERE id=?').bind(detail.expires_at,row.id));}
      if(!statements.length)return fail('INVALID_REQUEST');
    } else if(action==='revoke')statements.push(env.AJJAN_DB.prepare('UPDATE ajjan_keys SET revoked=1 WHERE id=?').bind(row.id));
    else if(action==='unban')statements.push(env.AJJAN_DB.prepare('UPDATE ajjan_keys SET revoked=0 WHERE id=? AND deleted_at IS NULL').bind(row.id));
    else if(action==='delete')statements.push(env.AJJAN_DB.prepare('UPDATE ajjan_keys SET revoked=1,deleted_at=? WHERE id=?').bind(now,row.id));
    else if(action==='restore'){
      const hasExpiry=body.duration!==undefined||body.expires_at!==undefined||body.lifetime===true;
      if(hasExpiry){detail.expires_at=expiry(body,now);if(detail.expires_at!==null&&detail.expires_at<=now)return fail('INVALID_EXPIRY',400,'Choose a future expiry before restoring this key.');statements.push(env.AJJAN_DB.prepare('UPDATE ajjan_keys SET expires_at=? WHERE id=?').bind(detail.expires_at,row.id));}
      else if(row.expires_at!==null&&row.expires_at<=now)return fail('KEY_EXPIRED',409,'Choose a new expiry to restore this expired key.');
      statements.push(env.AJJAN_DB.prepare('UPDATE ajjan_keys SET revoked=1,deleted_at=NULL WHERE id=?').bind(row.id));
    }
    else statements.push(env.AJJAN_DB.prepare('UPDATE ajjan_keys SET device_hash=NULL,device_id_ciphertext=NULL WHERE id=?').bind(row.id));
    if(action!=='update'||Object.hasOwn(detail,'expires_at'))statements.push(env.AJJAN_DB.prepare('DELETE FROM ajjan_script_sessions WHERE key_id=?').bind(row.id));
    statements.push(audit(action,row.id,detail));await env.AJJAN_DB.batch(statements);
    return json({ok:true});
  }catch(error){
    if(['INVALID_NOTE','INVALID_EXPIRY'].includes(error?.message))return fail(error.message,400,error.message==='INVALID_NOTE'?'Notes can contain up to 200 characters.':'Choose a valid duration from one minute up to ten years.');
    throw error;
  }
}

const EXPIRED_KEY_RETENTION = 15 * 60;

// Use the same recoverable Deleted state as an owner-initiated deletion.
// Keeping the records preserves generation counts, notes and owner recovery.
async function cleanupExpiredKeys(env, now = Math.floor(Date.now() / 1000)) {
  const results = await env.AJJAN_DB.batch([
    env.AJJAN_DB.prepare(`UPDATE ajjan_keys SET revoked=1,deleted_at=?
      WHERE deleted_at IS NULL AND expires_at IS NOT NULL AND expires_at<=?`)
      .bind(now, now - EXPIRED_KEY_RETENTION),
    env.AJJAN_DB.prepare(`DELETE FROM ajjan_script_sessions
      WHERE key_id IN (SELECT id FROM ajjan_keys WHERE deleted_at IS NOT NULL)`),
  ]);
  const count = Number(results[0].meta?.changes || 0);
  if (count) await env.AJJAN_DB.prepare('INSERT INTO ajjan_admin_audit(at,action,key_id,detail) VALUES(?,?,NULL,?)')
    .bind(now, 'auto-delete-expired', JSON.stringify({ count, retention_seconds: EXPIRED_KEY_RETENTION })).run();
  return count;
}

async function deviceEncryptionKey(secret) {
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('ajjan-device-storage-v1:' + secret));
  return crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const unhex = value => Uint8Array.from(value.match(/../g) || [], pair => parseInt(pair, 16));

async function encryptDeviceID(secret, keyID, device) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv,
    additionalData: new TextEncoder().encode(keyID) }, await deviceEncryptionKey(secret), new TextEncoder().encode(device));
  return 'v1:' + hex(iv) + ':' + hex(new Uint8Array(encrypted));
}

async function decryptDeviceID(secret, keyID, ciphertext) {
  if (!/^v1:[a-f0-9]{24}:[a-f0-9]{48,2080}$/.test(ciphertext || '')) return null;
  const [, nonce, encrypted] = ciphertext.split(':');
  try {
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unhex(nonce),
      additionalData: new TextEncoder().encode(keyID) }, await deviceEncryptionKey(secret), unhex(encrypted));
    return new TextDecoder().decode(plaintext);
  } catch { return null; }
}

// Cloudflare Pages advanced-mode Worker. No management secret is shipped to Lua or the browser.
const COOKIE = '__Host-ajjan-browser';
const ATTEMPT_COOKIE = '__Host-ajjan-checkpoint';
const ATTEMPT_SECONDS = 1200;
const HOURS = 15;
const MAX_KEYS = 3;
const CHECKPOINTS = 2;
const SESSION_SECONDS = 90;
const HEX64 = /^[a-f0-9]{64}$/i;
const KEY_FORMAT = /^(?:[a-f0-9]{32}|AJJANS-(?:[A-Z0-9]{4}-){2}[A-Z0-9]{4})$/i;
const KEY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const normalizeKey = key => /^[a-f0-9]{32}$/i.test(key) ? key.toLowerCase() : key.toUpperCase();
const encoder = new TextEncoder();
const messages = {
  KEY_INVALID: 'Enter your AJJANS-XXXX-XXXX-XXXX key.',
  KEY_INCORRECT: 'Wrong or deleted key.',
  KEY_EXPIRED: 'This key expired. Complete the tasks on the key page to generate a new key.',
  KEY_BANNED: 'This key has been revoked. Contact support.',
  KEY_HWID_LOCKED: 'This key is linked to another device.',
  DEVICE_INVALID: 'A valid device identifier is required.',
  SERVICE_UNAVAILABLE: 'The key service is temporarily unavailable. Please retry.',
  RATE_LIMITED: 'Too many requests. Wait a minute and retry.',
  KEY_LIMIT: 'You already have three active keys. Copy an existing key below.',
  TASKS_INCOMPLETE: 'Complete both checkpoint tasks before generating your key.',
  PROVIDER_PAUSED: 'New free keys are temporarily paused. Existing valid keys still work.',
};

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body), { status, headers: {
    'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', ...extra,
  }});
}
function fail(code, status = 400, message = messages[code] || code) {
  return json({ ok: false, code, message }, status);
}
function randomHex(bytes = 32) {
  return Array.from(crypto.getRandomValues(new Uint8Array(bytes)), n => n.toString(16).padStart(2, '0')).join('');
}
async function digest(value) {
  const data = await crypto.subtle.digest('SHA-256', encoder.encode(value));
  return Array.from(new Uint8Array(data), n => n.toString(16).padStart(2, '0')).join('');
}
async function deriveKey(secret, id) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode('ajjan-license-v2:' + id)));
  let bits = 0, buffer = 0, text = '';
  for (const byte of signature) {
    buffer = (buffer << 8) | byte; bits += 8;
    while (bits >= 5 && text.length < 12) { bits -= 5; text += KEY_ALPHABET[(buffer >>> bits) & 31]; }
    if (text.length === 12) break;
  }
  return 'AJJANS-' + text.match(/.{4}/g).join('-');
}
function equalSecret(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}
function cookieToken(request,name) {
  const value = request.headers.get('Cookie')?.split(';').map(v => v.trim()).find(v => v.startsWith(name + '='))?.slice(name.length + 1);
  return value && HEX64.test(value) ? value : null;
}
const browserToken=request=>cookieToken(request,COOKIE);
// A mutable progress counter is not a completion proof. Match provider receipts
// to the exact server-created attempt, browser, connection and checkpoint.
function receiptCountSQL(flowAlias) {
  return `(SELECT COUNT(DISTINCT r.step) FROM ajjan_checkpoint_receipts r
    JOIN ajjan_checkpoint_attempts a ON a.proof_hash=r.proof_hash
    WHERE r.flow_id=${flowAlias}.id AND a.flow_id=r.flow_id AND a.step=r.step
    AND a.browser_hash=${flowAlias}.browser_hash AND a.ip_hash=${flowAlias}.ip_hash
    AND a.provider=${flowAlias}.provider AND a.verified_at=r.created_at
    AND a.opened_at<=a.verified_at AND a.verified_at<a.expires_at)`;
}
function safeLink(value) {
  try { const url = new URL(value); return url.protocol === 'https:' && !url.username && !url.password ? url : null; }
  catch { return null; }
}
function issuancePaused(env,provider) {
  return String(env['PAUSE_'+provider.toUpperCase()+'_ISSUANCE']||'').toLowerCase()==='true';
}
function configured(env, provider) {
  if (issuancePaused(env,provider)) return false;
  if (provider === 'linkvertise') return !!(safeLink(env.LINKVERTISE_LINK) && safeLink(env.LINKVERTISE_LINK_2) && HEX64.test(env.LINKVERTISE_ANTI_BYPASS_TOKEN || ''));
  return !!(safeLink(env.LOOTLABS_LINK) && safeLink(env.LOOTLABS_LINK_2) && HEX64.test(env.LOOTLABS_API_TOKEN || '') && HEX64.test(env.LOOTLABS_POSTBACK_SECRET || ''));
}
async function readJSON(request) {
  if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) throw new Error('BAD_BODY');
  const reader = request.body?.getReader();
  if (!reader) throw new Error('BAD_BODY');
  const chunks = []; let length = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    length += value.length;
    if (length > 4096) { await reader.cancel(); throw new Error('BAD_BODY'); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  const body = JSON.parse(new TextDecoder().decode(bytes));
  if (!body || Array.isArray(body) || typeof body !== 'object') throw new Error('BAD_BODY');
  return body;
}
function keyProblem(key, now, deviceHash) {
  if (!key) return 'KEY_INCORRECT';
  if (key.deleted_at !== undefined && key.deleted_at !== null) return 'KEY_INCORRECT';
  if (key.revoked) return 'KEY_BANNED';
  if (key.expires_at !== null && key.expires_at <= now) return 'KEY_EXPIRED';
  if (deviceHash && key.device_hash && key.device_hash !== deviceHash) return 'KEY_HWID_LOCKED';
  return null;
}
const LINKVERTISE_HASH = /^[A-Za-z0-9_-]{64}$/;
function hashKind(value) {
  if (!value) return 'none';
  if (/^[a-f0-9]+$/i.test(value)) return 'hex';
  if (/^[A-Za-z0-9]+$/.test(value)) return 'alnum';
  return 'other:' + [...new Set(value.replace(/[A-Za-z0-9]/g, ''))].join('').slice(0, 10);
}
// Strip anything that looks like a token or hash before storing provider replies.
function redact(text) {
  return String(text).slice(0, 300).replace(/[A-Za-z0-9_-]{32,}/g, '[redacted]');
}
// Keeps the last 50 provider callback results without raw credentials or IPs.
async function note(env, now, step, reason, detail, provider='linkvertise') {
  try {
    detail={...detail,provider};
    console.log(provider+'-return', JSON.stringify({ step, reason, ...detail }));
    await env.AJJAN_DB.batch([
      env.AJJAN_DB.prepare('CREATE TABLE IF NOT EXISTS ajjan_debug_log (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, step INTEGER, reason TEXT, detail TEXT)'),
      env.AJJAN_DB.prepare('INSERT INTO ajjan_debug_log(at,step,reason,detail) VALUES(?,?,?,?)').bind(now, step, reason, JSON.stringify(detail).slice(0, 1000)),
      env.AJJAN_DB.prepare('DELETE FROM ajjan_debug_log WHERE id <= (SELECT MAX(id) - 50 FROM ajjan_debug_log)'),
    ]);
  } catch {}
}
function postbackValue(params,name) {
  const placeholder='{'+name.toUpperCase()+'}';
  const values=[...new Set(params.getAll(name).filter(value=>value&&value.toUpperCase()!==placeholder&&value.toUpperCase()!==encodeURIComponent(placeholder)))];
  return values.length===1?values[0]:null;
}
// Preserve the full internal flow ID in a shorter, alphanumeric provider ID.
function lootClickID(flow,step) {return 'L'+BigInt('0x'+flow).toString(36).padStart(50,'0')+step;}
function parseLootClickID(value) {
  if(typeof value!=='string')return null;
  const compact=/^L([0-9a-z]{50})([12])$/i.exec(value);
  if(compact){let number=0n;for(const char of compact[1].toLowerCase())number=number*36n+BigInt(parseInt(char,36));const flow=number.toString(16).padStart(64,'0');return flow.length===64?{flow,step:Number(compact[2]),format:'compact'}:null;}
  const legacy=/^([a-f0-9]{64})\.([12])$/i.exec(value);
  if(legacy)return {flow:legacy[1].toLowerCase(),step:Number(legacy[2]),format:'legacy'};
  // A provider may strip the suffix from an older, overlong first-step ID.
  // Such IDs can credit step 1 only; they can never advance checkpoint 2.
  if(/^[a-f0-9]{64}$/i.test(value))return {flow:value.toLowerCase(),step:1,format:'legacy_first_only'};
  return null;
}
function verifiedLinkvertiseReply(text) {
  const reply = text.trim();
  if (reply === 'TRUE') return true;
  try {
    const value = JSON.parse(reply);
    return value === true || (!!value && typeof value === 'object' && !Array.isArray(value)
      && (value.status === true || value.status === 'TRUE' || value.status === 'true'));
  } catch { return false; }
}

export function createService({ fetcher = fetch, clock = () => Math.floor(Date.now() / 1000), script = null } = {}) {
  async function rateLimit(env, request, group, limit, now, ctx) {
    const bucket = Math.floor(now / 60);
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const id = await digest(group + ':' + ip + ':' + bucket);
    const row = await env.AJJAN_DB.prepare(`INSERT INTO ajjan_rate_limits(id,bucket,hits) VALUES(?,?,1)
      ON CONFLICT(id) DO UPDATE SET hits=hits+1 RETURNING hits`).bind(id, bucket).first();
    if (row.hits === 1 && ctx?.waitUntil) {
      ctx.waitUntil(env.AJJAN_DB.batch([
        env.AJJAN_DB.prepare('DELETE FROM ajjan_rate_limits WHERE bucket < ?').bind(bucket - 10),
        env.AJJAN_DB.prepare('DELETE FROM ajjan_script_sessions WHERE expires_at <= ?').bind(now),
      ]).catch(() => {}));
    }
    return row.hits <= limit;
  }
  async function issueFlowKey(env, flow, now) {
    if (flow.renew_key_id) return null;
    const id = randomHex(16);
    const raw = await deriveKey(env.KEY_SECRET, id);
    const keyHash = await digest(raw);
    await env.AJJAN_DB.batch([
      env.AJJAN_DB.prepare(`INSERT INTO ajjan_keys(id,key_hash,browser_hash,flow_id,created_at,expires_at,key_format,source,note)
        SELECT ?,?,?,?,?,?,2,'ads','Ads key system' WHERE EXISTS (SELECT 1 FROM ajjan_flows f WHERE id=? AND browser_hash=? AND state='verified' AND renew_key_id IS NULL AND expires_at>? AND ${receiptCountSQL('f')}=2)
        AND EXISTS (SELECT 1 FROM ajjan_checkpoint_progress WHERE flow_id=? AND completed=2)
        AND NOT EXISTS (SELECT 1 FROM ajjan_keys WHERE flow_id=?)
        AND (SELECT COUNT(*) FROM ajjan_keys WHERE browser_hash=? AND revoked=0 AND (expires_at IS NULL OR expires_at>?)) < ?`)
        .bind(id, keyHash, flow.browser_hash, flow.id, now, now + HOURS * 3600, flow.id, flow.browser_hash, now, flow.id, flow.id, flow.browser_hash, now, MAX_KEYS),
      env.AJJAN_DB.prepare(`UPDATE ajjan_flows SET state='claimed' WHERE id=? AND EXISTS (SELECT 1 FROM ajjan_keys WHERE flow_id=?)`).bind(flow.id, flow.id),
    ]);
    return env.AJJAN_DB.prepare('SELECT * FROM ajjan_keys WHERE flow_id=?').bind(flow.id).first();
  }
  async function displayKey(env, row) {
    const key = await deriveKey(env.KEY_SECRET, row.id);
    if (row.key_format !== 2) {
      await env.AJJAN_DB.prepare(`UPDATE ajjan_keys SET legacy_key_hash=COALESCE(legacy_key_hash,key_hash),key_hash=?,key_format=2 WHERE id=? AND key_format!=2`)
        .bind(await digest(key),row.id).run();
    }
    return key;
  }
  async function progress(env, flowID) {
    await env.AJJAN_DB.prepare('INSERT OR IGNORE INTO ajjan_checkpoint_progress(flow_id,completed) VALUES(?,0)').bind(flowID).run();
    return (await env.AJJAN_DB.prepare('SELECT completed FROM ajjan_checkpoint_progress WHERE flow_id=?').bind(flowID).first()).completed;
  }
  async function recordCheckpoint(env, flow, step, proofHash, now, attempt) {
    await env.AJJAN_DB.batch([
      env.AJJAN_DB.prepare(`UPDATE ajjan_checkpoint_attempts SET verified_at=?,proof_hash=?
        WHERE token_hash=? AND flow_id=? AND step=? AND browser_hash=? AND ip_hash=?
        AND provider=? AND verified_at IS NULL AND opened_at<=? AND expires_at>?
        AND EXISTS(SELECT 1 FROM ajjan_checkpoint_progress p JOIN ajjan_flows f ON f.id=p.flow_id
        WHERE f.id=? AND f.state='pending' AND f.expires_at>? AND p.completed=?)`)
        .bind(now,proofHash,attempt.token_hash,flow.id,step,flow.browser_hash,flow.ip_hash,flow.provider,now,now,flow.id,now,step-1),
      env.AJJAN_DB.prepare(`INSERT INTO ajjan_checkpoint_receipts(proof_hash,flow_id,step,created_at)
        SELECT ?,?,?,? WHERE EXISTS(SELECT 1 FROM ajjan_checkpoint_attempts WHERE token_hash=? AND flow_id=? AND step=? AND proof_hash=? AND verified_at=?)`)
        .bind(proofHash,flow.id,step,now,attempt.token_hash,flow.id,step,proofHash,now),
      env.AJJAN_DB.prepare(`UPDATE ajjan_checkpoint_progress SET completed=? WHERE flow_id=? AND completed=?
        AND EXISTS(SELECT 1 FROM ajjan_checkpoint_receipts WHERE proof_hash=? AND flow_id=? AND step=?)`)
        .bind(step,flow.id,step-1,proofHash,flow.id,step),
      env.AJJAN_DB.prepare(`UPDATE ajjan_flows SET state='verified' WHERE id=? AND state='pending'
        AND EXISTS(SELECT 1 FROM ajjan_checkpoint_progress WHERE flow_id=? AND completed=2)
        AND ${receiptCountSQL('ajjan_flows')}=2`).bind(flow.id,flow.id),
    ]);
    const accepted=await env.AJJAN_DB.prepare(`SELECT 1 AS found FROM ajjan_checkpoint_receipts r JOIN ajjan_checkpoint_attempts a ON a.proof_hash=r.proof_hash
      WHERE r.proof_hash=? AND r.flow_id=? AND r.step=? AND a.token_hash=? AND a.verified_at IS NOT NULL`).bind(proofHash,flow.id,step,attempt.token_hash).first();
    return accepted ? progress(env, flow.id) : null;
  }
  function backToKeys(origin, result) {
    return new Response(null, { status: 303, headers: { Location: origin + '/getkey#' + result,
      'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' }});
  }
  async function requestProvider(url, options) {
    // Workers supports manual/follow, and rejects the Fetch-standard "error" mode.
    // Provider 3xx responses fail the explicit response.ok checks below.
    return fetcher(url, { ...options, signal: AbortSignal.timeout(8000), redirect: 'manual' });
  }

  return { async fetch(request, env, ctx = {}) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/$/, '');
    if (!path.startsWith('/api/keys/')) return env.ASSETS.fetch(request);
    const origin = env.PUBLIC_ORIGIN || url.origin;
    const now = clock();
    try {
      if (request.method === 'OPTIONS') return new Response(null, { status: 405 });
      const suppliedOrigin = request.headers.get('Origin');
      if (suppliedOrigin && suppliedOrigin !== origin) return fail('ORIGIN_DENIED', 403, 'Request origin is not allowed.');
      if (request.method==='POST' && ['/api/keys/start','/api/keys/renew','/api/keys/generate','/api/keys/cancel'].includes(path)) {
        if (suppliedOrigin!==origin || (request.headers.get('Sec-Fetch-Site') && !['same-origin','none'].includes(request.headers.get('Sec-Fetch-Site')))) return fail('ORIGIN_DENIED',403,'Open the key page to start or complete your tasks.');
      }
      const basicReady = !!(env.AJJAN_DB && HEX64.test(env.KEY_SECRET || ''));
      if (path === '/api/keys/config' && request.method === 'GET') {
        return json({ ok: true, hours: HOURS, max_keys: MAX_KEYS, checkpoints: CHECKPOINTS, security_revision:3, renewals:false, expired_key_retention_seconds:EXPIRED_KEY_RETENTION,
          paused_providers:['linkvertise','lootlabs'].filter(provider=>issuancePaused(env,provider)), providers: {
          linkvertise: basicReady && configured(env, 'linkvertise'), lootlabs: basicReady && configured(env, 'lootlabs'),
        }});
      }
      if (!basicReady) return fail('SERVICE_UNAVAILABLE', 503);
      if (request.method==='POST' && ['/api/keys/start','/api/keys/renew','/api/keys/generate'].includes(path)
        && ['linkvertise','lootlabs'].some(provider=>issuancePaused(env,provider))
        && !['linkvertise','lootlabs'].some(provider=>configured(env,provider))) return fail('PROVIDER_PAUSED',503);

      if (path === '/api/keys/renew' && request.method === 'POST') return fail('RENEWAL_DISABLED',410,'Key renewal is no longer available. Complete both tasks to generate a new key.');
      if (path === '/api/keys/cancel' && request.method === 'POST') {
        if (!await rateLimit(env,request,'cancel',20,now,ctx)) return fail('RATE_LIMITED',429);
        const token=browserToken(request);
        if (token) await env.AJJAN_DB.prepare(`UPDATE ajjan_flows SET expires_at=? WHERE browser_hash=? AND state IN ('pending','verified') AND expires_at>?`).bind(now,await digest(token),now).run();
        return json({ok:true});
      }
      if (path === '/api/keys/generate' && request.method === 'POST') {
        if (!await rateLimit(env,request,'generate',30,now,ctx)) return fail('RATE_LIMITED',429);
        const body=await readJSON(request), token=browserToken(request);
        if (!token) return fail('TASKS_INCOMPLETE',409);
        const browserHash=await digest(token);
        if (body.flow_id!==undefined && (typeof body.flow_id!=='string'||!HEX64.test(body.flow_id))) return fail('TASKS_INCOMPLETE',409);
        const flow=body.flow_id
          ? await env.AJJAN_DB.prepare('SELECT * FROM ajjan_flows WHERE id=? AND browser_hash=?').bind(body.flow_id,browserHash).first()
          : await env.AJJAN_DB.prepare(`SELECT * FROM ajjan_flows WHERE browser_hash=? AND state IN ('pending','verified') AND expires_at>? ORDER BY created_at DESC LIMIT 1`).bind(browserHash,now).first();
        if (flow?.renew_key_id) return fail('RENEWAL_DISABLED',410,'Start new tasks to generate a new key.');
        if (flow && issuancePaused(env,flow.provider)) return fail('PROVIDER_PAUSED',503);
        if (!flow || flow.expires_at<=now || (flow.state!=='verified' && flow.state!=='claimed') || await progress(env,flow.id)!==2) return fail('TASKS_INCOMPLETE',409);
        if (flow.ip_hash!==await digest(request.headers.get('CF-Connecting-IP')||'unknown')) return fail('CONNECTION_CHANGED',409,'Your connection changed. Start both checkpoints again from the key page.');
        const attested=await env.AJJAN_DB.prepare(`SELECT ${receiptCountSQL('f')} AS total FROM ajjan_flows f WHERE f.id=?`).bind(flow.id).first();
        if (attested?.total!==2) return fail('TASKS_INCOMPLETE',409);
        const key=await issueFlowKey(env,flow,now);
        if (!key) return fail('KEY_LIMIT',409);
        const problem=keyProblem(key,now);
        if (problem) return fail(problem,403);
        return json({ok:true,key:await displayKey(env,key),expires_at:key.expires_at,message:'Congratulations! Your key has been generated.'});
      }
      if (path === '/api/keys/start' && request.method === 'POST') {
        if (!await rateLimit(env, request, 'start', 20, now, ctx)) return fail('RATE_LIMITED', 429);
        const { provider } = await readJSON(request);
        if (['linkvertise','lootlabs'].includes(provider) && issuancePaused(env,provider)) return fail('PROVIDER_PAUSED',503);
        if (!['linkvertise', 'lootlabs'].includes(provider) || !configured(env, provider)) {
          return fail('PROVIDER_UNAVAILABLE', 503, 'This checkpoint is currently unavailable. Try another provider.');
        }
        const token = browserToken(request) || randomHex();
        const browserHash = await digest(token);
        const ipHash=await digest(request.headers.get('CF-Connecting-IP')||'unknown');
        let flow = await env.AJJAN_DB.prepare(`SELECT * FROM ajjan_flows WHERE browser_hash=? AND state IN ('pending','verified') AND expires_at>? ORDER BY created_at DESC LIMIT 1`).bind(browserHash, now).first();
        if (flow?.renew_key_id) {
          await env.AJJAN_DB.prepare('UPDATE ajjan_flows SET expires_at=? WHERE id=?').bind(now,flow.id).run();
          flow=null;
        }
        if (flow) {
          const done=await progress(env,flow.id);
          const receipts=await env.AJJAN_DB.prepare(`SELECT ${receiptCountSQL('f')} AS total FROM ajjan_flows f WHERE f.id=?`).bind(flow.id).first();
          if (flow.ip_hash!==ipHash || receipts.total!==done) {
            await env.AJJAN_DB.prepare('UPDATE ajjan_flows SET expires_at=? WHERE id=?').bind(now,flow.id).run();
            flow=null;
          }
        }
        const count = await env.AJJAN_DB.prepare(`SELECT COUNT(*) AS total FROM ajjan_keys WHERE browser_hash=? AND deleted_at IS NULL AND revoked=0 AND (expires_at IS NULL OR expires_at>?)`).bind(browserHash,now).first();
        if (count.total >= MAX_KEYS) return fail('KEY_LIMIT', 409);
        if (flow?.state==='verified') return json({ok:true,ready:true,step:2,total_steps:2});
        if (!flow || flow.provider!==provider) {
          if (flow) await env.AJJAN_DB.prepare('UPDATE ajjan_flows SET expires_at=? WHERE id=?').bind(now,flow.id).run();
          flow = { id: randomHex(), browser_hash: browserHash, ip_hash:ipHash, provider };
          await env.AJJAN_DB.prepare(`INSERT INTO ajjan_flows(id,browser_hash,ip_hash,provider,created_at,expires_at) VALUES(?,?,?,?,?,?)`).bind(flow.id, browserHash, flow.ip_hash, provider, now, now + 3600).run();
        }
        const step = (await progress(env, flow.id)) + 1;
        let target = safeLink(provider === 'linkvertise'
          ? (step === 1 ? env.LINKVERTISE_LINK : env.LINKVERTISE_LINK_2)
          : (step === 1 ? env.LOOTLABS_LINK : env.LOOTLABS_LINK_2));
        if (provider === 'lootlabs') {
          const response = await requestProvider('https://creators.lootlabs.gg/api/public/url_encryptor', {
            method: 'POST', headers: { Authorization: 'Bearer ' + env.LOOTLABS_API_TOKEN, 'Content-Type': 'application/json' },
            body: JSON.stringify({ destination_url: origin + '/getkey#key-return=lootlabs&step=' + step }),
          });
          if (!response.ok) return fail('PROVIDER_UNAVAILABLE', 502, 'Could not open this checkpoint. Please retry.');
          const data = await response.json();
          if (!['created', 'fetched'].includes(data.type) || typeof data.message !== 'string' || !data.message) {
            return fail('PROVIDER_UNAVAILABLE', 502, 'Could not open this checkpoint. Please retry.');
          }
          // LootLabs returns an already URL-encoded string; normalize before URLSearchParams encodes it.
          let encrypted = data.message;
          try { encrypted = decodeURIComponent(encrypted); } catch {}
          // LootLabs' short ID is an opaque bare query, e.g. /s?abcd.
          // Mutating its searchParams rewrites that ID to abcd=.
          const fragment=target.hash;target.hash='';
          const parameters=new URLSearchParams({data:encrypted,puid:lootClickID(flow.id,step)});
          target=new URL(target.href+(target.search?'&':'?')+parameters.toString()+fragment);
        }
        const attemptToken=randomHex(), attemptHash=await digest(attemptToken);
        await env.AJJAN_DB.batch([
          env.AJJAN_DB.prepare(`UPDATE ajjan_checkpoint_attempts SET expires_at=? WHERE flow_id=? AND step=? AND verified_at IS NULL AND expires_at>?`).bind(now,flow.id,step,now),
          env.AJJAN_DB.prepare(`INSERT INTO ajjan_checkpoint_attempts(token_hash,flow_id,browser_hash,ip_hash,provider,step,opened_at,expires_at) VALUES(?,?,?,?,?,?,?,?)`)
            .bind(attemptHash,flow.id,browserHash,ipHash,provider,step,now,now+ATTEMPT_SECONDS),
        ]);
        const opened=json({ ok: true, url: target.href, step, total_steps: CHECKPOINTS }, 200, {
          'Set-Cookie': `${COOKIE}=${token}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`,
        });
        opened.headers.append('Set-Cookie',`${ATTEMPT_COOKIE}=${attemptToken}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=${ATTEMPT_SECONDS}`);
        return opened;
      }

      if (/^\/api\/keys\/return\/linkvertise\/[12]$/.test(path) && request.method === 'GET') {
        const step = Number(path.slice(-1));
        const token = browserToken(request);
        const proof = url.searchParams.get('hash') || '';
        // What arrived, without values: used to tell which check failed.
        const seen = { cookie: !!token, params: [...url.searchParams.keys()].slice(0, 10), hash_len: proof.length, hash_kind: hashKind(proof) };
        const failed = async (reason, extra = {}) => {
          await note(env, now, step, reason, { ...seen, ...extra });
          return backToKeys(origin, 'key-error=' + reason);
        };
        if (issuancePaused(env,'linkvertise')) return failed('paused');
        if (!configured(env, 'linkvertise')) return failed('provider');
        if (!await rateLimit(env, request, 'callback', 30, now, ctx)) return failed('rate');
        if (!token) return failed('cookie');
        if (!proof) return failed('nohash');
        // Linkvertise checks the hash itself; only reject obvious junk here.
        if (!LINKVERTISE_HASH.test(proof)) return failed('hashformat');
        const browserHash = await digest(token);
        const flow = await env.AJJAN_DB.prepare(`SELECT * FROM ajjan_flows WHERE browser_hash=? AND provider='linkvertise' AND state='pending' AND expires_at>? ORDER BY created_at DESC LIMIT 1`).bind(browserHash, now).first();
        if (!flow) return failed('session');
        const done = await progress(env, flow.id);
        if (done !== step - 1) return failed('order', { completed: done });
        if (flow.ip_hash!==await digest(request.headers.get('CF-Connecting-IP')||'unknown')) return failed('connection');
        const attemptToken=cookieToken(request,ATTEMPT_COOKIE);
        if (!attemptToken) return failed('checkpoint_start');
        const attempt=await env.AJJAN_DB.prepare(`SELECT * FROM ajjan_checkpoint_attempts WHERE token_hash=? AND flow_id=? AND step=? AND provider='linkvertise'
          AND browser_hash=? AND ip_hash=? AND verified_at IS NULL AND opened_at<=? AND expires_at>?`)
          .bind(await digest(attemptToken),flow.id,step,browserHash,flow.ip_hash,now,now).first();
        if (!attempt) return failed('checkpoint_session');
        const proofHash = await digest('linkvertise:' + proof);
        if (await env.AJJAN_DB.prepare('SELECT 1 AS found FROM ajjan_checkpoint_receipts WHERE proof_hash=?').bind(proofHash).first()) return failed('reused');
        const verifyURL = new URL('https://publisher.linkvertise.com/api/v1/anti_bypassing');
        verifyURL.searchParams.set('token', env.LINKVERTISE_ANTI_BYPASS_TOKEN);
        verifyURL.searchParams.set('hash', proof);
        const response = await requestProvider(verifyURL.href, { method: 'POST' });
        const reply = await response.text();
        if (!response.ok || !verifiedLinkvertiseReply(reply)) {
          return failed('rejected', { status: response.status, reply: redact(reply) });
        }
        const completed = await recordCheckpoint(env, flow, step, proofHash, now,attempt);
        if (completed===null) return failed('checkpoint_session');
        await note(env, now, step, 'ok', { ...seen, completed, provider_verified:true,attempt_verified:true });
        if (completed < CHECKPOINTS) return backToKeys(origin, 'key-step=2&provider=linkvertise');
        return backToKeys(origin, 'key-ready');
      }

      if (path.startsWith('/api/keys/lootlabs-postback/') && request.method === 'GET') {
        const secret = path.slice('/api/keys/lootlabs-postback/'.length);
        if (!configured(env, 'lootlabs') || !equalSecret(secret, env.LOOTLABS_POSTBACK_SECRET)) return fail('NOT_FOUND', 404);
        const rawClick=postbackValue(url.searchParams,'click_id');
        const clickID = parseLootClickID(rawClick);
        const flowID = clickID?.flow;
        const step = Number(clickID?.step);
        const uniqueID = postbackValue(url.searchParams,'unique_id') || '';
        const visitorIP = postbackValue(url.searchParams,'ip') || '';
        const seen={flow_prefix:flowID?.slice(0,12)||null,click_length:rawClick?.length||0,click_format:clickID?.format||'unrecognized',click_is_decimal:!!rawClick&&/^\d+$/.test(rawClick),click_fields:url.searchParams.getAll('click_id').length,ip_fields:url.searchParams.getAll('ip').length,unique_fields:url.searchParams.getAll('unique_id').length,has_click:!!clickID,has_ip:!!visitorIP,has_unique:!!uniqueID};
        const rejected=async(reason,code,status)=>{await note(env,now,Number.isFinite(step)?step:0,reason,seen,'lootlabs');return fail(code,status);};
        if (!flowID || !uniqueID || uniqueID.length > 256 || !visitorIP || visitorIP.length > 64) return rejected('invalid_payload','INVALID_POSTBACK',400);
        const flow = await env.AJJAN_DB.prepare(`SELECT * FROM ajjan_flows WHERE id=? AND provider='lootlabs' AND expires_at>?`).bind(flowID, now).first();
        if (!flow) return rejected('unknown_or_expired_flow','INVALID_POSTBACK',403);
        if (flow.ip_hash !== await digest(visitorIP)) return rejected('connection_mismatch','INVALID_POSTBACK',403);
        const proofHash = await digest('lootlabs:' + uniqueID);
        const existing = await env.AJJAN_DB.prepare('SELECT flow_id,step FROM ajjan_checkpoint_receipts WHERE proof_hash=?').bind(proofHash).first();
        if (existing) {if(existing.flow_id!==flowID||existing.step!==step)return rejected('reused_completion','PROOF_REUSED',409);await note(env,now,step,'duplicate',seen,'lootlabs');return json({ok:true});}
        if (flow.state !== 'pending' || await progress(env, flowID) !== step - 1) return rejected('checkpoint_order','CHECKPOINT_ORDER',409);
        const attempt=await env.AJJAN_DB.prepare(`SELECT * FROM ajjan_checkpoint_attempts WHERE flow_id=? AND step=? AND provider='lootlabs'
          AND browser_hash=? AND ip_hash=? AND verified_at IS NULL AND opened_at<=? AND expires_at>? ORDER BY opened_at DESC LIMIT 1`)
          .bind(flowID,step,flow.browser_hash,flow.ip_hash,now,now).first();
        if (!attempt) return rejected('expired_or_missing_visit','CHECKPOINT_NOT_STARTED',409);
        const completed = await recordCheckpoint(env, flow, step, proofHash, now,attempt);
        if (completed===null) return rejected('replaced_visit','CHECKPOINT_NOT_STARTED',409);
        await note(env,now,step,'ok',{...seen,completed},'lootlabs');
        if (completed < CHECKPOINTS) return json({ ok: true, completed, total: CHECKPOINTS });
        return json({ok:true,completed,total:CHECKPOINTS,ready:true});
      }

      if (path === '/api/keys/mine' && request.method === 'GET') {
        if (!await rateLimit(env, request, 'mine', 240, now, ctx)) return fail('RATE_LIMITED', 429);
        await cleanupExpiredKeys(env,now);
        const token = browserToken(request);
        if (!token) return json({ ok: true, keys: [], pending: false });
        const browserHash = await digest(token);
        const rows = await env.AJJAN_DB.prepare(`SELECT * FROM ajjan_keys WHERE browser_hash=? AND revoked=0 AND deleted_at IS NULL ORDER BY created_at DESC`).bind(browserHash).all();
        const pending = await env.AJJAN_DB.prepare(`SELECT f.id,f.provider,${receiptCountSQL('f')} AS completed FROM ajjan_flows f
          WHERE f.browser_hash=? AND f.renew_key_id IS NULL AND f.state IN ('pending','verified') AND f.expires_at>?
          ORDER BY f.created_at DESC LIMIT 1`).bind(browserHash, now).first();
        const keys=[];
        for (const key of rows.results) keys.push({key:await displayKey(env,key),id:key.id,expires_at:key.expires_at,delete_at:key.expires_at===null?null:key.expires_at+EXPIRED_KEY_RETENTION,device_bound:!!key.device_hash,hwid_locked:!!key.device_hash,status:key.expires_at!==null&&key.expires_at<=now?'expired':'active',remaining_seconds:key.expires_at===null?null:Math.max(0,key.expires_at-now)});
        return json({ ok: true, keys, active_count:keys.filter(k=>k.status==='active').length,pending: !!pending, checkpoint: pending ? { id:pending.id,provider: pending.provider, completed: pending.completed, total: CHECKPOINTS,ready:pending.completed===2 } : null });
      }

      if (path === '/api/keys/validate' && request.method === 'POST') {
        if (!await rateLimit(env,request,'validate',120,now,ctx)) return fail('RATE_LIMITED',429);
        const body=await readJSON(request);
        if (typeof body.key!=='string'||!KEY_FORMAT.test(body.key)) return fail('KEY_INVALID');
        if (typeof body.device!=='string'||body.device.length<8||body.device.length>256) return fail('DEVICE_INVALID');
        const hash=await digest(normalizeKey(body.key)), deviceHash=await digest(body.device);
        const key=await env.AJJAN_DB.prepare('SELECT * FROM ajjan_keys WHERE key_hash=? OR legacy_key_hash=?').bind(hash,hash).first();
        const problem=keyProblem(key,clock(),deviceHash);
        if (problem) return fail(problem,403);
        if (!key.device_hash) return fail('KEY_NOT_VERIFIED',403,'Verify this key in the Ajjans key screen first.');
        return json({ok:true,code:'KEY_VALID',data:{device_bound:true,auth_expire:key.expires_at||-1}});
      }

      if (path === '/api/keys/authenticate' && request.method === 'POST') {
        if (!await rateLimit(env, request, 'auth', 120, now, ctx)) return fail('RATE_LIMITED', 429);
        const body = await readJSON(request);
        if (typeof body.key !== 'string' || !KEY_FORMAT.test(body.key)) return fail('KEY_INVALID');
        if (typeof body.device !== 'string' || body.device.length < 8 || body.device.length > 256) return fail('DEVICE_INVALID');
        const deviceHash = await digest(body.device);
        const keyHash = await digest(normalizeKey(body.key));
        const key = await env.AJJAN_DB.prepare(`UPDATE ajjan_keys SET device_hash=COALESCE(device_hash,?), last_used_at=?
          WHERE (key_hash=? OR legacy_key_hash=?) AND revoked=0 AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at>?)
          AND (device_hash IS NULL OR device_hash=?) RETURNING *`).bind(deviceHash, now, keyHash,keyHash, now, deviceHash).first();
        if (!key) {
          const existing = await env.AJJAN_DB.prepare('SELECT * FROM ajjan_keys WHERE key_hash=? OR legacy_key_hash=?').bind(keyHash,keyHash).first();
          return fail(keyProblem(existing, now, deviceHash) || 'KEY_INCORRECT', 403);
        }
        if (!key.device_id_ciphertext) {
          const ciphertext=await encryptDeviceID(env.KEY_SECRET,key.id,body.device);
          await env.AJJAN_DB.prepare(`UPDATE ajjan_keys SET device_id_ciphertext=? WHERE id=? AND device_hash=?
            AND revoked=0 AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at>?)`).bind(ciphertext,key.id,deviceHash,now).run();
        }
        const session = randomHex();
        await env.AJJAN_DB.prepare('INSERT INTO ajjan_script_sessions(token_hash,key_id,device_hash,expires_at) VALUES(?,?,?,?)').bind(await digest(session), key.id, deviceHash, now + SESSION_SECONDS).run();
        return json({ ok: true, code: 'KEY_VALID', session, data: { auth_expire: key.expires_at || -1 } });
      }

      if (path === '/api/keys/script' && request.method === 'POST') {
        if (!await rateLimit(env, request, 'script', 120, now, ctx)) return fail('RATE_LIMITED', 429);
        const token = request.headers.get('Authorization')?.replace(/^Bearer /, '') || '';
        const device = request.headers.get('X-Ajjan-Device') || '';
        if (!HEX64.test(token) || device.length < 8 || device.length > 256) return fail('SESSION_INVALID', 403, 'Verify your key again.');
        const tokenHash = await digest(token);
        const deviceHash = await digest(device);
        const row = await env.AJJAN_DB.prepare(`SELECT s.key_id, s.expires_at AS session_expiry, s.device_hash AS session_device,
          k.* FROM ajjan_script_sessions s JOIN ajjan_keys k ON k.id=s.key_id WHERE s.token_hash=?`).bind(tokenHash).first();
        if (!row || row.session_expiry <= now || row.session_device !== deviceHash) return fail('SESSION_INVALID', 403, 'Verify your key again.');
        const problem = keyProblem(row, now, deviceHash);
        if (problem) return fail(problem, 403);
        if (script === null && !env.AJJAN_SCRIPTS) return fail('SCRIPT_UNAVAILABLE', 503, 'The script is temporarily unavailable. Retry shortly.');
        const payload = script !== null ? { body: script, size: script.length } : await env.AJJAN_SCRIPTS.get('steal-an-egg.lua');
        if (!payload || payload.size === 0) return fail('SCRIPT_UNAVAILABLE', 503, 'The script is temporarily unavailable. Retry shortly.');
        // Recheck and consume atomically, including revocation/expiry changes during the R2 read.
        const consumed = await env.AJJAN_DB.prepare(`DELETE FROM ajjan_script_sessions WHERE token_hash=? AND expires_at>?
          AND EXISTS(SELECT 1 FROM ajjan_keys WHERE id=ajjan_script_sessions.key_id AND revoked=0 AND deleted_at IS NULL
          AND (expires_at IS NULL OR expires_at>?) AND device_hash=?) RETURNING key_id`).bind(tokenHash, clock(), clock(), deviceHash).first();
        if (!consumed) return fail('SESSION_INVALID', 403, 'Verify your key again.');
        await env.AJJAN_DB.prepare('UPDATE ajjan_keys SET executions=executions+1 WHERE id=?').bind(row.key_id).run();
        return new Response(payload.body, { headers: { 'Content-Type': 'text/plain; charset=utf-8',
          'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }});
      }

      if (path.startsWith('/api/keys/admin/') && request.method === 'POST') {
        return await handleAdmin(request,env,ctx,{path,now,json,fail,readJSON,digest,deriveKey,displayKey,equalSecret,randomHex,rateLimit,cleanupExpiredKeys,decryptDeviceID,expiredKeyRetention:EXPIRED_KEY_RETENTION});
      }
      return fail('NOT_FOUND', 404);
    } catch (error) {
      if (path.startsWith('/api/keys/return/linkvertise/')) {
        await note(env, now, Number(path.slice(-1)) || 0, 'network', { error: redact(error?.name + ': ' + error?.message) });
        return backToKeys(origin, 'key-error=network');
      }
      if (error?.message === 'BAD_BODY' || error instanceof SyntaxError) return fail('INVALID_REQUEST', 400, 'Send a valid JSON request.');
      // Never include provider URLs, secrets, key values, or stack traces in a response or log.
      return fail('SERVICE_UNAVAILABLE', 503);
    }
  }};
}



// A fixed-destination, owner-authenticated move. No credential or game source
// belongs in the public website repository; configuration is encrypted in D1.
export const MAIN_ORIGIN = 'https://ajjans-hub.pages.dev';
export const OLD_ORIGIN = 'https://ajjans-key.pages.dev';
const SECRET_NAMES = ['KEY_SECRET','ADMIN_TOKEN','ADMIN_PANEL_TOKEN','LINKVERTISE_ANTI_BYPASS_TOKEN','LINKVERTISE_LINK','LINKVERTISE_LINK_2','LOOTLABS_API_TOKEN','LOOTLABS_POSTBACK_SECRET','LOOTLABS_LINK','LOOTLABS_LINK_2','PAUSE_LINKVERTISE_ISSUANCE','PAUSE_LOOTLABS_ISSUANCE'];
const TABLES = {"ajjan_flows": ["id", "browser_hash", "ip_hash", "provider", "state", "created_at", "expires_at", "renew_key_id"], "ajjan_checkpoint_progress": ["flow_id", "completed"], "ajjan_checkpoint_receipts": ["proof_hash", "flow_id", "step", "created_at"], "ajjan_checkpoint_attempts": ["token_hash", "flow_id", "browser_hash", "ip_hash", "provider", "step", "opened_at", "expires_at", "verified_at", "proof_hash"], "ajjan_keys": ["id", "key_hash", "legacy_key_hash", "key_format", "browser_hash", "flow_id", "created_at", "expires_at", "device_hash", "device_id_ciphertext", "revoked", "last_used_at", "executions", "source", "note", "deleted_at"], "ajjan_key_renewals": ["flow_id", "key_id", "renewed_at", "applied"], "ajjan_script_sessions": ["token_hash", "key_id", "device_hash", "expires_at"], "ajjan_provider_proofs": ["proof_hash", "created_at"], "ajjan_rate_limits": ["id", "bucket", "hits"], "ajjan_admin_sessions": ["token_hash", "credential_hash", "created_at", "expires_at"], "ajjan_admin_audit": ["id", "at", "action", "key_id", "detail"], "ajjan_debug_log": ["id", "at", "step", "reason", "detail"]};
const SCHEMA = "PRAGMA foreign_keys = ON;\nCREATE TABLE IF NOT EXISTS ajjan_flows ( id TEXT PRIMARY KEY, browser_hash TEXT NOT NULL, ip_hash TEXT NOT NULL, provider TEXT NOT NULL CHECK (provider IN ('linkvertise', 'lootlabs')), state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'verified', 'claimed')), created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, renew_key_id TEXT REFERENCES ajjan_keys(id) );\nCREATE INDEX IF NOT EXISTS ajjan_flows_browser ON ajjan_flows(browser_hash, provider, state);\nCREATE TABLE IF NOT EXISTS ajjan_checkpoint_progress ( flow_id TEXT PRIMARY KEY REFERENCES ajjan_flows(id) ON DELETE CASCADE, completed INTEGER NOT NULL DEFAULT 0 CHECK (completed BETWEEN 0 AND 2) );\nCREATE TABLE IF NOT EXISTS ajjan_checkpoint_receipts ( proof_hash TEXT PRIMARY KEY, flow_id TEXT NOT NULL REFERENCES ajjan_flows(id), step INTEGER NOT NULL CHECK (step IN (1, 2)), created_at INTEGER NOT NULL );\nCREATE TABLE IF NOT EXISTS ajjan_checkpoint_attempts ( token_hash TEXT PRIMARY KEY, flow_id TEXT NOT NULL REFERENCES ajjan_flows(id), browser_hash TEXT NOT NULL, ip_hash TEXT NOT NULL, provider TEXT NOT NULL CHECK (provider IN ('linkvertise','lootlabs')), step INTEGER NOT NULL CHECK (step IN (1,2)), opened_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, verified_at INTEGER, proof_hash TEXT UNIQUE );\nCREATE INDEX IF NOT EXISTS ajjan_attempt_flow ON ajjan_checkpoint_attempts(flow_id,step);\nCREATE TABLE IF NOT EXISTS ajjan_keys ( id TEXT PRIMARY KEY, key_hash TEXT NOT NULL UNIQUE, legacy_key_hash TEXT, key_format INTEGER NOT NULL DEFAULT 1, browser_hash TEXT, flow_id TEXT UNIQUE REFERENCES ajjan_flows(id), created_at INTEGER NOT NULL, expires_at INTEGER, device_hash TEXT, device_id_ciphertext TEXT, revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)), last_used_at INTEGER, executions INTEGER NOT NULL DEFAULT 0, source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('ads','manual')), note TEXT NOT NULL DEFAULT '', deleted_at INTEGER );\nCREATE INDEX IF NOT EXISTS ajjan_keys_browser ON ajjan_keys(browser_hash, expires_at);\nCREATE UNIQUE INDEX IF NOT EXISTS ajjan_keys_legacy ON ajjan_keys(legacy_key_hash);\nCREATE INDEX IF NOT EXISTS ajjan_keys_cleanup ON ajjan_keys(expires_at) WHERE deleted_at IS NULL;\nCREATE TABLE IF NOT EXISTS ajjan_key_renewals ( flow_id TEXT PRIMARY KEY REFERENCES ajjan_flows(id), key_id TEXT NOT NULL REFERENCES ajjan_keys(id), renewed_at INTEGER NOT NULL, applied INTEGER NOT NULL DEFAULT 0 CHECK (applied IN (0,1)) );\nCREATE TABLE IF NOT EXISTS ajjan_script_sessions ( token_hash TEXT PRIMARY KEY, key_id TEXT NOT NULL REFERENCES ajjan_keys(id) ON DELETE CASCADE, device_hash TEXT NOT NULL, expires_at INTEGER NOT NULL );\nCREATE INDEX IF NOT EXISTS ajjan_script_sessions_expiry ON ajjan_script_sessions(expires_at);\nCREATE TABLE IF NOT EXISTS ajjan_provider_proofs ( proof_hash TEXT PRIMARY KEY, created_at INTEGER NOT NULL );\nCREATE TABLE IF NOT EXISTS ajjan_rate_limits ( id TEXT PRIMARY KEY, bucket INTEGER NOT NULL, hits INTEGER NOT NULL );\nCREATE INDEX IF NOT EXISTS ajjan_rate_bucket ON ajjan_rate_limits(bucket);\nCREATE TABLE IF NOT EXISTS ajjan_admin_sessions ( token_hash TEXT PRIMARY KEY, credential_hash TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL );\nCREATE TABLE IF NOT EXISTS ajjan_admin_audit ( id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, action TEXT NOT NULL, key_id TEXT, detail TEXT NOT NULL );\nCREATE TABLE IF NOT EXISTS ajjan_debug_log (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, step INTEGER, reason TEXT, detail TEXT);";
const STATE_SCHEMA = "CREATE TABLE IF NOT EXISTS ajjan_site_move(id INTEGER PRIMARY KEY CHECK(id=1),state TEXT NOT NULL,lock_until INTEGER NOT NULL DEFAULT 0,receipt TEXT);";
const CONFIG_SCHEMA = "CREATE TABLE IF NOT EXISTS ajjan_service_config(id INTEGER PRIMARY KEY CHECK(id=1),cipher TEXT NOT NULL,moved_at INTEGER NOT NULL,active INTEGER NOT NULL DEFAULT 0,receipt TEXT NOT NULL);\nCREATE TABLE IF NOT EXISTS ajjan_browser_transfers(ticket_hash TEXT PRIMARY KEY,expires_at INTEGER NOT NULL);\nCREATE TABLE IF NOT EXISTS ajjan_private_scripts(name TEXT PRIMARY KEY,cipher TEXT NOT NULL);";
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
function browserCookie(request,name){const value=request.headers.get('Cookie')?.split(';').map(c=>c.trim()).find(c=>c.startsWith(name+'='))?.slice(name.length+1);return validSecret(value)?value:null;}
const redirect = location => new Response(null,{status:303,headers:{...noCache,Location:location}});
function safeNext(next){return typeof next==='string'&&(next==='/getkey'||/^\/api\/keys\/return\/linkvertise\/[12](?:\?[^#\r\n]*)?$/.test(next));}

export function createMainSite({service,fetcher=fetch}={}){
  let cached=null,privateScriptCache=null;
  async function configuration(env){
    if(cached&&cached.db===env.AJJAN_DB&&cached.key===env.KEY_CONFIG_SECRET&&cached.until>Date.now())return cached.value;
    const row=await env.AJJAN_DB.prepare('SELECT cipher FROM ajjan_service_config WHERE id=1 AND active=1').first();
    if(!row)return null;
    const value=await unseal(env.KEY_CONFIG_SECRET,row.cipher,'ajjan-main-configuration-v1',true);
    cached={db:env.AJJAN_DB,key:env.KEY_CONFIG_SECRET,until:Date.now()+30000,value};return value;
  }
  async function importSnapshot(request,env){
    if(!validSecret(env.MIGRATION_ADMIN_TOKEN)||!same(bearer(request),env.MIGRATION_ADMIN_TOKEN))return reply({ok:false,code:'UNAUTHORIZED'},401);
    if(request.headers.has('Origin'))return reply({ok:false,code:'ORIGIN_DENIED'},403);
    if(!env.AJJAN_DB||!validSecret(env.KEY_CONFIG_SECRET))return reply({ok:false,code:'NOT_READY'},503);
    await env.AJJAN_DB.exec(CONFIG_SCHEMA);
    if(await env.AJJAN_DB.prepare('SELECT id FROM ajjan_service_config WHERE id=1 AND active=1').first())return reply({ok:false,code:'ALREADY_MOVED'},409);
    const snapshot=await request.json();
    if(snapshot.origin!==OLD_ORIGIN||snapshot.target!==MAIN_ORIGIN||!validSecret(snapshot.env?.KEY_SECRET)||!validSecret(snapshot.env?.ADMIN_PANEL_TOKEN)||!same(snapshot.authorizer_hash,await sha(env.MIGRATION_ADMIN_TOKEN)))return reply({ok:false,code:'INVALID_SNAPSHOT'},400);
    if(Math.abs(nowSeconds()-snapshot.at)>120||typeof snapshot.script!=='string'||snapshot.script.length<100)return reply({ok:false,code:'INVALID_SNAPSHOT'},400);
    const environment={};for(const name of SECRET_NAMES)if(typeof snapshot.env[name]==='string')environment[name]=snapshot.env[name];
    for(const [table,columns] of Object.entries(TABLES)){
      const rows=snapshot.tables?.[table];if(!Array.isArray(rows)||rows.length>100000||rows.some(row=>!row||typeof row!=='object'||Object.keys(row).some(k=>!columns.includes(k))))return reply({ok:false,code:'INVALID_SNAPSHOT'},400);
    }
    await env.AJJAN_DB.exec(SCHEMA);
    const statements=[env.AJJAN_DB.prepare('UPDATE ajjan_flows SET renew_key_id=NULL')];
    for(const table of [...Object.keys(TABLES)].reverse())statements.push(env.AJJAN_DB.prepare('DELETE FROM '+table));
    const renewals=[];
    for(const [table,columns] of Object.entries(TABLES))for(const original of snapshot.tables[table]){
      const row={...original};if(table==='ajjan_flows'&&row.renew_key_id){renewals.push({id:row.id,key:row.renew_key_id});row.renew_key_id=null;}
      statements.push(env.AJJAN_DB.prepare('INSERT INTO '+table+'('+columns.join(',')+') VALUES('+columns.map(()=>'?').join(',')+')').bind(...columns.map(k=>row[k]??null)));
    }
    for(const row of renewals)statements.push(env.AJJAN_DB.prepare('UPDATE ajjan_flows SET renew_key_id=? WHERE id=?').bind(row.key,row.id));
    const cipher=await seal(env.KEY_CONFIG_SECRET,{env:environment},'ajjan-main-configuration-v1',true);
    const scriptCipher=await seal(env.KEY_CONFIG_SECRET,{script:snapshot.script},'ajjan-main-script-v1',true);
    if(scriptCipher.length>1900000)return reply({ok:false,code:'SNAPSHOT_TOO_LARGE'},413);
    const receipt={ok:true,origin:MAIN_ORIGIN,counts:Object.fromEntries(Object.entries(snapshot.tables).map(([name,rows])=>[name,rows.length]))};
    statements.push(env.AJJAN_DB.prepare('INSERT INTO ajjan_service_config(id,cipher,moved_at,active,receipt) VALUES(1,?,?,0,?) ON CONFLICT(id) DO UPDATE SET cipher=excluded.cipher,moved_at=excluded.moved_at,active=0,receipt=excluded.receipt').bind(cipher,nowSeconds(),JSON.stringify(receipt)));
    statements.push(env.AJJAN_DB.prepare("INSERT INTO ajjan_private_scripts(name,cipher) VALUES('steal-an-egg.lua',?) ON CONFLICT(name) DO UPDATE SET cipher=excluded.cipher").bind(scriptCipher));
    await env.AJJAN_DB.batch(statements);cached=null;privateScriptCache=null;
    return reply(receipt);
  }
  return {async fetch(request,env,ctx){
    const url=new URL(request.url),path=url.pathname;
    if(path==='/api/keys/migration/import'&&request.method==='POST'){
      try{return await importSnapshot(request,env);}catch{return reply({ok:false,code:'MIGRATION_FAILED'},503);}
    }
    if(path==='/api/keys/migration/activate'&&request.method==='POST'){
      if(!validSecret(env.MIGRATION_ADMIN_TOKEN)||!same(bearer(request),env.MIGRATION_ADMIN_TOKEN)||request.headers.has('Origin'))return reply({ok:false,code:'UNAUTHORIZED'},401);
      try{
        const row=await env.AJJAN_DB.prepare('UPDATE ajjan_service_config SET active=1 WHERE id=1 RETURNING receipt').first();
        if(!row)return reply({ok:false,code:'NOT_READY'},503);
        cached=null;return reply({...JSON.parse(row.receipt),active:true});
      }catch{return reply({ok:false,code:'NOT_READY'},503);}
    }
    if(!path.startsWith('/api/keys/'))return env.ASSETS.fetch(request);
    let config;try{config=await configuration(env);}catch{}
    if(!config)return reply({ok:false,code:'SERVICE_UNAVAILABLE',message:'The key service is moving to the main website. Please retry shortly.'},503);
    const active={...config.env,...env,PUBLIC_ORIGIN:MAIN_ORIGIN,AJJAN_SCRIPTS:{get:async name=>{
      if(name!=='steal-an-egg.lua')return null;
      if(!privateScriptCache||privateScriptCache.db!==env.AJJAN_DB||privateScriptCache.key!==env.KEY_CONFIG_SECRET||privateScriptCache.until<Date.now()){
        const row=await env.AJJAN_DB.prepare('SELECT cipher FROM ajjan_private_scripts WHERE name=?').bind(name).first();
        if(!row)return null;
        const value=await unseal(env.KEY_CONFIG_SECRET,row.cipher,'ajjan-main-script-v1',true);
        privateScriptCache={db:env.AJJAN_DB,key:env.KEY_CONFIG_SECRET,until:Date.now()+30000,body:value.script};
      }
      return {body:privateScriptCache.body,size:privateScriptCache.body.length};
    }}};
    if(path==='/api/keys/migration/accept'&&request.method==='GET'){
      try{
        const encoded=url.searchParams.get('ticket')||'';if(encoded.length>5000)throw Error('BAD_TICKET');
        const ticket=await unseal(config.env.KEY_SECRET,encoded,'ajjan-browser-move-v1');
        if(!validSecret(ticket.browser)||!validSecret(ticket.nonce)||ticket.at>nowSeconds()+5||ticket.at<nowSeconds()-60||!safeNext(ticket.next))throw Error('BAD_TICKET');
        const used=await env.AJJAN_DB.prepare('INSERT OR IGNORE INTO ajjan_browser_transfers(ticket_hash,expires_at) VALUES(?,?)').bind(await sha(encoded),ticket.at+60).run();
        if(!used.meta?.changes)throw Error('REUSED_TICKET');
        let keepCurrent=false;
        const current=browserCookie(request,'__Host-ajjan-browser');
        if(current&&ticket.next.startsWith('/api/keys/return/linkvertise/')){
          keepCurrent=!!await env.AJJAN_DB.prepare("SELECT id FROM ajjan_flows WHERE browser_hash=? AND provider='linkvertise' AND state='pending' AND expires_at>? LIMIT 1").bind(await sha(current),nowSeconds()).first();
        }
        if(current&&ticket.next==='/getkey')keepCurrent=!!await env.AJJAN_DB.prepare("SELECT id FROM ajjan_keys WHERE browser_hash=? AND deleted_at IS NULL UNION SELECT id FROM ajjan_flows WHERE browser_hash=? AND state IN ('pending','verified') AND expires_at>? LIMIT 1").bind(await sha(current),await sha(current),nowSeconds()).first();
        const result=redirect(MAIN_ORIGIN+ticket.next);
        if(!keepCurrent){
          result.headers.append('Set-Cookie',`__Host-ajjan-browser=${ticket.browser}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=2592000`);
          if(validSecret(ticket.attempt))result.headers.append('Set-Cookie',`__Host-ajjan-checkpoint=${ticket.attempt}; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age=1200`);
        }
        ctx?.waitUntil?.(env.AJJAN_DB.prepare('DELETE FROM ajjan_browser_transfers WHERE expires_at<?').bind(nowSeconds()).run());
        return result;
      }catch{return redirect(MAIN_ORIGIN+'/getkey#key-error=session');}
    }
    if(request.headers.has('X-Ajjan-Bridge')){
      if(!same(request.headers.get('X-Ajjan-Bridge'),config.env.ADMIN_PANEL_TOKEN))return reply({ok:false,code:'UNAUTHORIZED'},401);
      const headers=new Headers(request.headers),ip=headers.get('X-Ajjan-Original-IP');
      if(!ip||! /^[a-f0-9.:]{3,64}$/i.test(ip))return reply({ok:false,code:'UNAUTHORIZED'},401);
      headers.set('CF-Connecting-IP',ip);
      if(headers.get('Origin')===OLD_ORIGIN)headers.set('Origin',MAIN_ORIGIN);
      headers.delete('X-Ajjan-Bridge');headers.delete('X-Ajjan-Original-IP');
      request=new Request(request,{headers});
    }
    return service.fetch(request,active,ctx);
  }};
}

export function createLegacySite({service,script,fetcher=fetch}={}){
  async function handoff(request,next,env){
    const browser=browserCookie(request,'__Host-ajjan-browser');
    if(!browser)return redirect(MAIN_ORIGIN+next);
    const ticket=await seal(env.KEY_SECRET,{browser,attempt:browserCookie(request,'__Host-ajjan-checkpoint'),nonce:random(),at:nowSeconds(),next},'ajjan-browser-move-v1');
    return redirect(MAIN_ORIGIN+'/api/keys/migration/accept?ticket='+encodeURIComponent(ticket));
  }
  return {async fetch(request,env,ctx){
    const url=new URL(request.url),path=url.pathname;
    let state;try{state=await env.AJJAN_DB.prepare('SELECT * FROM ajjan_site_move WHERE id=1').first();}catch{}
    if(state?.state==='complete'&&path==='/api/keys/admin/migrate-main'&&request.method==='POST'){
      if(![env.ADMIN_PANEL_TOKEN,env.ADMIN_TOKEN].some(token=>validSecret(token)&&same(token,bearer(request)))||request.headers.has('Origin'))return reply({ok:false,code:'UNAUTHORIZED'},401);
      return fetcher(MAIN_ORIGIN+'/api/keys/migration/activate',{method:'POST',redirect:'manual',headers:{Authorization:request.headers.get('Authorization')}});
    }
    if(state?.state==='complete'){
      if(path==='/getkey'||path==='/getkey.html')return handoff(request,'/getkey',env);
      if(/^\/api\/keys\/return\/linkvertise\/[12]$/.test(path)&&request.method==='GET')return handoff(request,path+url.search,env);
      if(!path.startsWith('/api/keys/'))return redirect(MAIN_ORIGIN+path+url.search);
      const headers=new Headers(request.headers);
      headers.set('X-Ajjan-Bridge',env.ADMIN_PANEL_TOKEN);headers.set('X-Ajjan-Original-IP',request.headers.get('CF-Connecting-IP')||'unknown');
      return fetcher(new Request(MAIN_ORIGIN+path+url.search,{method:request.method,headers,body:['GET','HEAD'].includes(request.method)?undefined:request.body,redirect:'manual',duplex:'half'}));
    }
    if(path==='/api/keys/admin/migrate-main'&&request.method==='POST'){
      if(![env.ADMIN_PANEL_TOKEN,env.ADMIN_TOKEN].some(token=>validSecret(token)&&same(token,bearer(request))))return reply({ok:false,code:'UNAUTHORIZED'},401);
      if(request.headers.has('Origin'))return reply({ok:false,code:'ORIGIN_DENIED'},403);
      await env.AJJAN_DB.exec(STATE_SCHEMA);
      const locked=await env.AJJAN_DB.prepare("INSERT INTO ajjan_site_move(id,state,lock_until) VALUES(1,'copying',?) ON CONFLICT(id) DO UPDATE SET state='copying',lock_until=excluded.lock_until WHERE ajjan_site_move.state!='complete' AND ajjan_site_move.lock_until<? RETURNING id").bind(nowSeconds()+120,nowSeconds()).first();
      if(!locked)return reply({ok:false,code:'MOVE_IN_PROGRESS'},409);
      try{
        const results=await env.AJJAN_DB.batch(Object.keys(TABLES).map(table=>env.AJJAN_DB.prepare('SELECT * FROM '+table)));
        const tables=Object.fromEntries(Object.keys(TABLES).map((table,index)=>[table,results[index].results]));
        const secrets={};for(const name of SECRET_NAMES)if(typeof env[name]==='string')secrets[name]=env[name];
        const snapshot={origin:OLD_ORIGIN,target:MAIN_ORIGIN,at:nowSeconds(),authorizer_hash:await sha(bearer(request)),env:secrets,tables,script};
        const response=await fetcher(MAIN_ORIGIN+'/api/keys/migration/import',{method:'POST',redirect:'manual',signal:AbortSignal.timeout(90000),headers:{'Content-Type':'application/json',Authorization:request.headers.get('Authorization')},body:JSON.stringify(snapshot)});
        const receipt=await response.json();
        if(!response.ok||!receipt.ok||receipt.origin!==MAIN_ORIGIN||Object.keys(TABLES).some(table=>receipt.counts?.[table]!==tables[table].length))throw Error('IMPORT_NOT_CONFIRMED');
        await env.AJJAN_DB.prepare("UPDATE ajjan_site_move SET state='complete',lock_until=0,receipt=? WHERE id=1").bind(JSON.stringify(receipt)).run();
        const activated=await fetcher(MAIN_ORIGIN+'/api/keys/migration/activate',{method:'POST',redirect:'manual',headers:{Authorization:request.headers.get('Authorization')}});
        return activated;
      }catch{
        await env.AJJAN_DB.prepare("UPDATE ajjan_site_move SET state='pending',lock_until=0 WHERE id=1 AND state='copying'").run();
        return reply({ok:false,code:'DESTINATION_NOT_READY'},503);
      }
    }
    if(state?.state==='copying'&&state.lock_until>nowSeconds()&&path.startsWith('/api/keys/'))return reply({ok:false,code:'SERVICE_UNAVAILABLE',message:'The key service is moving. Please retry shortly.'},503);
    return service.fetch(request,env,ctx);
  }};
}

export default createMainSite({service:createService()});
