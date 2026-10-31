(() => {
  'use strict';
  const byId=id=>document.getElementById(id);
  const notice=byId('key-notice'), list=byId('key-list'), count=byId('key-count'), refresh=byId('key-refresh'), generate=byId('key-generate'), toast=byId('key-toast');
  if (!notice||!list||!generate) return;
  const providers=[...document.querySelectorAll('[data-key-provider]')];
  let config=null, checkpoint=null, keys=[], busy=false, refreshing=false, timer=null, polls=0, toastTimer=null, announcedReady=null;
  function say(message,state='') { notice.textContent=message; notice.dataset.error=String(state==='error'); notice.dataset.success=String(state==='success'); }
  function notify(title,message,state='success') {
    clearTimeout(toastTimer); toast.dataset.state=state;
    toast.querySelector('strong').textContent=title; toast.querySelector('p').textContent=message;
    toast.querySelector('.key-toast__icon').textContent=state==='success'?'✓':'!';
    toast.hidden=false; toastTimer=setTimeout(()=>{toast.hidden=true;},7000);
  }
  toast.querySelector('button').addEventListener('click',()=>{toast.hidden=true;});
  async function api(path,body) {
    const response=await fetch('/api/keys/'+path,{credentials:'same-origin',cache:'no-store',...(body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)})});
    const data=await response.json(); if (!response.ok||!data.ok) throw new Error(data.message||'The key service is unavailable. Please retry.'); return data;
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); return true; } catch {}
    const input=document.createElement('textarea'); input.value=text; input.style.cssText='position:fixed;left:-10000px'; document.body.append(input); input.select();
    let ok=false; try {ok=document.execCommand('copy');} catch {} input.remove(); return ok;
  }
  const expired=k=>k.expires_at!==null&&k.expires_at<=Math.floor(Date.now()/1000);
  const freeIssuancePaused=()=>!!config?.paused_providers?.length&&!Object.values(config.providers).some(Boolean);
  function remaining(key) {
    if (key.expires_at===null) return 'Lifetime access';
    const seconds=Math.max(0,key.expires_at-Math.floor(Date.now()/1000));
    if (!seconds) {
      const left=Math.max(0,(key.delete_at??key.expires_at+900)-Math.floor(Date.now()/1000));
      return left?'Expired · deletes in '+Math.ceil(left/60)+'m':'Expired · deleting…';
    }
    return `${Math.floor(seconds/3600)}h ${Math.floor(seconds%3600/60)}m remaining`;
  }
  function renderKeys() {
    keys=keys.filter(k=>k.expires_at===null||(k.delete_at??k.expires_at+900)>Math.floor(Date.now()/1000));
    list.replaceChildren(); count.textContent=`${keys.filter(k=>!expired(k)).length} / ${config?.max_keys||3} active`;
    if (!keys.length) { const p=document.createElement('p'); p.className='keys-panel__notice'; p.textContent='Your generated keys will appear here. Expired keys are deleted after 15 minutes. Complete both tasks to generate a new key.'; list.append(p); return; }
    for (const key of keys) {
      const isExpired=expired(key), row=document.createElement('article'); row.className='key-row'; row.dataset.expired=String(isExpired);
      const text=document.createElement('div'), code=document.createElement('code'); code.className='key-row__code'; code.textContent=key.key;
      const badges=document.createElement('div'); badges.className='key-row__badges';
      for (const [label,type] of [[isExpired?'Expired':'Active',isExpired?'expired':'active'],[key.hwid_locked?'HWID locked':'HWID not linked',key.hwid_locked?'locked':'unlocked']]) {
        const badge=document.createElement('span'); badge.className='key-badge'; badge.dataset.type=type; badge.textContent=label; badges.append(badge);
      }
      const meta=document.createElement('p'); meta.className='key-row__meta'; meta.textContent=remaining(key);
      text.append(code,badges,meta);
      const actions=document.createElement('div'); actions.className='key-row__actions';
      const copyButton=document.createElement('button'); copyButton.type='button'; copyButton.className='btn btn--glass btn--sm'; copyButton.textContent='Copy key'; copyButton.setAttribute('aria-label','Copy '+key.key);
      copyButton.addEventListener('click',async()=>{const ok=await copy(key.key); copyButton.textContent=ok?'Copied!':'Select key above'; if (ok) notify('Key copied','Paste it into the Ajjans key screen.'); setTimeout(()=>{copyButton.textContent='Copy key';},2000);});
      actions.append(copyButton);
      row.append(text,actions); list.append(row);
    }
  }
  function renderProgress() {
    const done=checkpoint?.completed||0, left=2-done;
    byId('key-task-title').textContent='Complete your tasks';
    byId('key-progress-label').textContent=`${done} of 2 complete · ${left} remaining`;
    byId('key-progress').setAttribute('aria-valuenow',String(done)); byId('key-progress-fill').style.width=(done*50)+'%';
    for (let step=1;step<=2;step++) {const el=byId('key-step-'+step), complete=done>=step; el.dataset.complete=String(complete); el.querySelector('.key-step__icon').textContent=complete?'✓':String(step); el.querySelector('small').textContent=complete?'Completed':step===done+1?'Next task':'Not completed';}
    generate.textContent='Generate Key'; generate.dataset.ready=String(done===2);
    generate.disabled=freeIssuancePaused();
    providers.forEach(link=>{const label=link.querySelector('[data-key-provider-label]');if(label)label.textContent=done===2?'tasks complete':checkpoint?.provider===link.dataset.keyProvider&&done===1?'continue step 2':'get key';});
    if (freeIssuancePaused()) {
      byId('key-task-title').textContent='New free keys temporarily paused';
      say('New free keys are temporarily paused. Existing valid keys still work.');
    } else if (done===2) {
      say('Both tasks are complete. Press Generate Key to create your key.','success');
      if (announcedReady!==checkpoint.id) {announcedReady=checkpoint.id;notify('Tasks complete!','You can now press Generate Key.');}
    } else if (done===1) say('Checkpoint 1 is done. Complete checkpoint 2 above to finish.');
    else say('Complete both checkpoints above, then press Generate Key.');
  }
  function poll() { if(timer||polls>=120||!checkpoint||checkpoint.ready)return; timer=setTimeout(async()=>{timer=null;polls++;if(!document.hidden)await loadKeys();else poll();},5000); }
  async function loadKeys(manual=false) {
    if(refreshing)return;refreshing=true;refresh.disabled=true;
    try {const data=await api('mine');keys=data.keys;checkpoint=data.checkpoint||null;renderKeys();renderProgress();poll();if(manual&&!checkpoint)notify('Keys refreshed','Your key list is up to date.','info');}
    catch(error){say(error.message,'error');}
    finally{refreshing=false;refresh.disabled=false;}
  }
  for(const link of providers){
    link.setAttribute('aria-disabled','true');link.addEventListener('click',async event=>{
      event.preventDefault();if(busy)return;
      if(!config?.providers[link.dataset.keyProvider]){notify('Provider unavailable',config?.paused_providers?.includes(link.dataset.keyProvider)?'This provider is temporarily paused. Existing valid keys still work.':'This provider is unavailable. Please choose an available provider.','error');return;}
      busy=true;link.setAttribute('aria-busy','true');
      try{const data=await api('start',{provider:link.dataset.keyProvider});if(data.ready){await loadKeys();byId('your-keys').scrollIntoView({behavior:'smooth'});}else window.location.assign(data.url);}
      catch(error){say(error.message,'error');notify('Could not open checkpoint',error.message,'error');}
      finally{busy=false;link.removeAttribute('aria-busy');}
    });
  }
  async function claimKey(){
    if(busy)return;busy=true;generate.disabled=true;
    try{
      const data=await api('generate',checkpoint?{flow_id:checkpoint.id}:{});await loadKeys();say(data.message,'success');notify('Congratulations! Key generated',data.message);
    }
    catch(error){say(error.message,'error');notify(checkpoint?.ready?'Could not generate key':'Complete your tasks first',error.message,'error');}
    finally{busy=false;generate.disabled=freeIssuancePaused();}
  }
  generate.addEventListener('click',()=>claimKey());
  refresh.addEventListener('click',()=>{polls=0;loadKeys(true);});
  window.addEventListener('focus',()=>loadKeys());document.addEventListener('visibilitychange',()=>{if(!document.hidden)loadKeys();});
  setInterval(()=>{if(!document.hidden)loadKeys();},30000);
  (async()=>{
    const fragment=new URLSearchParams(location.hash.slice(1));
    const errors={checkpoint:'The checkpoint could not be verified.',session:'Your checkpoint session expired. Start again.',limit:'You already have three active keys.',provider:'This provider is unavailable.',rate:'Too many attempts. Wait a minute.',network:'Could not reach the checkpoint provider.',order:'Complete checkpoints in order using the provider button.',cookie:'Start the checkpoint from this page in this same browser.',nohash:'Linkvertise did not send a completion code. Complete every step.',hashformat:'The provider sent an invalid completion code.',reused:'That checkpoint was already used. Open a new checkpoint.',rejected:'Linkvertise could not confirm this checkpoint. Complete every step.',checkpoint_start:'Open each checkpoint using the provider button on this page. Direct return links are not accepted.',checkpoint_session:'This checkpoint visit expired or was replaced. Open the provider button again.',connection:'Your connection changed. Start both checkpoints again using the same connection.'};
    const errorCode=fragment.get('key-error');if(location.hash.startsWith('#key-'))history.replaceState(null,'',location.pathname+location.search);
    errors.paused='New free keys are temporarily paused. Existing valid keys still work.';
    try{config=await api('config');providers.forEach(link=>link.setAttribute('aria-disabled',String(!config.providers[link.dataset.keyProvider])));await loadKeys();if(errorCode){const message=(errors[errorCode]||errors.checkpoint)+' (code: '+errorCode.replace(/[^a-z_]/g,'').slice(0,20)+')';say(message,'error');notify('Checkpoint not verified',message,'error');}}
    catch{say('The key service is currently unavailable. Please return shortly.','error');}
  })();
})();
