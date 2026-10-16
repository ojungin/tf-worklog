/* ============ 기본 유틸 ============ */
const te=new TextEncoder(), td=new TextDecoder();
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const pad=n=>String(n).padStart(2,'0');
const ymd=d=>`${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;
const pYmd=s=>{const[a,b,c]=String(s).split('-').map(Number);return new Date(a,b-1,c)};
const DOW=['일','월','화','수','목','금','토'];
const fmtDT=ts=>{const d=new Date(ts);return `${ymd(d)} ${pad(d.getHours())}:${pad(d.getMinutes())}`};
const fmtMD=s=>{const d=pYmd(s);return `${d.getMonth()+1}.${d.getDate()} (${DOW[d.getDay()]})`};
const todayStr=()=>ymd(new Date());
const addDays=(d,n)=>{const x=new Date(d);x.setDate(x.getDate()+n);return x};
const weekStart=d=>{const x=new Date(d.getFullYear(),d.getMonth(),d.getDate());const k=(x.getDay()+6)%7;return addDays(x,-k)};
const rnd=n=>{const A='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';const b=crypto.getRandomValues(new Uint8Array(n));return [...b].map(x=>A[x%A.length]).join('')};
function b64(u8){let s='';for(let i=0;i<u8.length;i+=0x8000)s+=String.fromCharCode.apply(null,u8.subarray(i,i+0x8000));return btoa(s)}
const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));

/* ============ 암호화 (AES-256-GCM, PBKDF2-SHA256) ============
   - 워크스페이스 데이터키(DEK): 최초 설정 때 관리자 브라우저에서 생성. 서버로 평문 전송되지 않음.
   - 계정별로 DEK를 '비밀번호 파생키'로 감싸 key_wraps 테이블에 저장 → 로그인 시 브라우저에서 해제
   - 업무/회의록/코멘트/이름은 DEK로 암호화된 암호문만 Supabase로 전송·저장 */
const KDF_ITER=250000;
async function deriveKek(pw,salt,iter=KDF_ITER){
  const base=await crypto.subtle.importKey('raw',te.encode(pw),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:iter,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function encB(key,bytes){const iv=crypto.getRandomValues(new Uint8Array(12));const ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},key,bytes));return{iv:b64(iv),ct:b64(ct)}}
async function decB(key,o){return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(o.iv)},key,unb64(o.ct)))}
const encJ=o=>encB(S.dek,te.encode(JSON.stringify(o)));
const decJ=async o=>JSON.parse(td.decode(await decB(S.dek,o)));
async function wrapFor(pw,dekRaw){const salt=crypto.getRandomValues(new Uint8Array(16));const k=await deriveKek(pw,salt);return{salt:b64(salt),iter:KDF_ITER,wk:await encB(k,dekRaw)}}
async function unwrap(pw,w){const k=await deriveKek(pw,unb64(w.salt),w.iter);return decB(k,w.wk)}
const importDek=raw=>crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);

/* ============ Supabase ============ */
const CFG=window.TF_CONFIG||{};
const DOMAIN=CFG.emailDomain||'tf-worklog.local';
const emailOf=u=>`${u.trim().toLowerCase()}@${DOMAIN}`;
let sb=null;
const ERR={invalid_setup_token:'설정 토큰이 올바르지 않습니다.',already_initialized:'이미 초기 설정이 완료되었습니다. 로그인해 주세요.',username_taken:'이미 사용 중인 아이디입니다.',
  admin_only:'관리자만 할 수 있습니다.',inactive:'비활성화된 계정입니다.',unauthorized:'로그인이 만료되었습니다. 다시 로그인해 주세요.',cannot_change_self:'본인 계정에는 적용할 수 없습니다.',invalid_input:'입력값을 확인해 주세요. (아이디: 영문·숫자·._- 3~30자, 비밀번호 8자 이상)'};
async function fn(action,payload={}){
  const {data,error}=await sb.functions.invoke('admin-users',{body:{action,...payload}});
  if(error){let code='';try{code=(await error.context.json()).error}catch{}throw new Error(ERR[code]||('서버 처리 실패'+(code?` (${code})`:'')))}
  return data;
}
async function fetchAll(t){let out=[],from=0;for(;;){const{data,error}=await sb.from(t).select('*').range(from,from+999);if(error)throw error;out=out.concat(data);if(data.length<1000)break;from+=1000}return out}
const DEC={
  profiles:async r=>({id:r.id,username:r.username,role:r.role,active:r.active,createdAt:Date.parse(r.created_at),name:(await decJ(r.name_enc)).name}),
  tasks:async r=>({...await decJ(r.enc),id:r.id,owner:r.owner,createdAt:Date.parse(r.created_at),updatedAt:Date.parse(r.updated_at)}),
  meetings:async r=>({...await decJ(r.enc),id:r.id,author:r.author,createdAt:Date.parse(r.created_at),updatedAt:Date.parse(r.updated_at)}),
  comments:async r=>({...await decJ(r.enc),id:r.id,type:r.task_id?'task':'meeting',target:r.task_id||r.meeting_id,author:r.author,createdAt:Date.parse(r.created_at)}),
};
const MAPKEY={profiles:'accounts',tasks:'tasks',meetings:'meetings',comments:'comments'};

/* ============ 상태 ============ */
const S={dek:null,dekRaw:null,me:null,chan:null,lastSync:0,
  accounts:new Map(),tasks:new Map(),meetings:new Map(),comments:new Map(),
  view:'sched',month:new Date(new Date().getFullYear(),new Date().getMonth(),1),sel:todayStr(),scope:'mine',
  rep:{mode:'week',anchor:new Date(),member:'all'},open:new Set(),drafts:{},meetSel:null,meetQ:'',admQ:'',loaded:false};
const isAdmin=()=>S.me?.role==='admin';
const nameOf=id=>(id&&S.accounts.get(id)?.name)||'(삭제된 사용자)';
const canEditTask=t=>isAdmin()||t.owner===S.me.id;

/* ============ 부팅 / 게이트 ============ */
async function boot(){
  if(!window.supabase||!CFG.url||!CFG.anonKey||/YOUR-/.test(CFG.url)) return gate('config');
  sb=supabase.createClient(CFG.url,CFG.anonKey,{auth:{persistSession:false,autoRefreshToken:true}});
  const {data,error}=await sb.rpc('workspace_initialized');
  if(error) return gate('error',error);
  gate(data?'login':'setup');
}
const shell=body=>`<div class="gate wrap"><div class="gcard"><div class="gh"><b>닥터빌 TF 워크로그</b><span>잡스케줄러 · 업무 Report · 회의록 로그</span></div>${body}</div></div>`;
const lock=`<p class="lock"><span aria-hidden="true">🔒</span><span>업무·회의록·코멘트·이름은 이 브라우저에서 AES-256으로 암호화된 뒤 Supabase에 저장됩니다. 서버에는 암호문만 남습니다.</span></p>`;
function gate(kind,e){
  if(kind==='config') return $('#app').innerHTML=shell(`<div class="gb"><p style="margin:0"><b>설정 파일이 비어 있습니다.</b></p><p class="muted" style="margin:0">GitHub 저장소 Settings → Secrets and variables → Actions → <b>Variables</b>에 <span class="mono">SUPABASE_URL</span>, <span class="mono">SUPABASE_ANON_KEY</span>를 등록하고 Pages 배포를 다시 실행하세요. (로컬 실행 시에는 web/config.js 작성)</p></div>`);
  if(kind==='error') return $('#app').innerHTML=shell(`<div class="gb"><p style="margin:0">서버에 연결하지 못했습니다.</p><p class="muted" style="margin:0">config.js의 URL·키와 스키마(schema.sql) 적용 여부를 확인해 주세요.</p><p class="muted mono" style="margin:0;font-size:12px">${esc(e?.message||'')}</p></div>`);
  if(kind==='setup'){
    $('#app').innerHTML=shell(`<form id="fSetup" autocomplete="off">
      <div><b>최초 관리자 계정 만들기</b><p class="muted" style="margin:4px 0 0;font-size:13px">설치 때 Supabase Secret으로 정한 설정 토큰이 필요합니다. 이 계정으로 팀원 계정을 추가합니다.</p></div>
      <div class="field"><label for="su_tok">설정 토큰</label><input class="input" id="su_tok" required type="password" autocomplete="off"></div>
      <div class="field"><label for="su_id">관리자 아이디</label><input class="input" id="su_id" required minlength="3" maxlength="30" pattern="[A-Za-z0-9._-]+" title="영문, 숫자, . _ - 만 사용"></div>
      <div class="field"><label for="su_name">이름</label><input class="input" id="su_name" required maxlength="20"></div>
      <div class="field"><label for="su_pw">비밀번호 (8자 이상)</label><input class="input" id="su_pw" type="password" required minlength="8" autocomplete="new-password"></div>
      <div class="field"><label for="su_pw2">비밀번호 확인</label><input class="input" id="su_pw2" type="password" required minlength="8" autocomplete="new-password"></div>
      <div class="err" id="su_err"></div>
      <button class="btn primary" type="submit" id="su_btn">관리자 계정 생성</button>${lock}</form>`);
    $('#fSetup').onsubmit=async ev=>{ev.preventDefault();const err=$('#su_err');err.textContent='';
      const u=$('#su_id').value.trim(),nm=$('#su_name').value.trim(),pw=$('#su_pw').value;
      if(pw!==$('#su_pw2').value){err.textContent='비밀번호가 서로 다릅니다.';return}
      const btn=$('#su_btn');btn.disabled=true;btn.textContent='생성 중…';
      try{
        const k=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
        S.dekRaw=new Uint8Array(await crypto.subtle.exportKey('raw',k));S.dek=await importDek(S.dekRaw);
        await fn('bootstrap',{token:$('#su_tok').value,username:u,password:pw,name_enc:await encJ({name:nm}),wrap:await wrapFor(pw,S.dekRaw),check_enc:await encJ({ok:true})});
        const r=await login(u,pw);if(r!==true)throw new Error(r);
        startApp();
      }catch(e){err.textContent=e.message;btn.disabled=false;btn.textContent='관리자 계정 생성';S.dek=null;S.dekRaw=null}
    };return;
  }
  $('#app').innerHTML=shell(`<form id="fLogin" autocomplete="on">
    <div class="field"><label for="li_id">아이디</label><input class="input" id="li_id" required autocomplete="username"></div>
    <div class="field"><label for="li_pw">비밀번호</label><input class="input" id="li_pw" type="password" required autocomplete="current-password"></div>
    <div class="err" id="li_err"></div>
    <button class="btn primary" type="submit" id="li_btn">로그인</button>${lock}</form>`);
  $('#li_id').focus();
  $('#fLogin').onsubmit=async ev=>{ev.preventDefault();const err=$('#li_err');err.textContent='';
    const btn=$('#li_btn');btn.disabled=true;btn.textContent='확인 중…';
    const r=await login($('#li_id').value,$('#li_pw').value);
    if(r!==true){err.textContent=r;btn.disabled=false;btn.textContent='로그인';return}
    startApp();
  };
}
async function login(u,pw){
  const {data,error}=await sb.auth.signInWithPassword({email:emailOf(u),password:pw});
  if(error){
    if(/banned/i.test(error.message))return '비활성화된 계정입니다. 관리자에게 문의하세요.';
    if(/invalid login|credentials/i.test(error.message))return '아이디 또는 비밀번호가 올바르지 않습니다.';
    return '로그인 실패: '+error.message;
  }
  const uid=data.user.id;
  try{
    const {data:p}=await sb.from('profiles').select('*').eq('id',uid).maybeSingle();
    if(!p||!p.active){await sb.auth.signOut();return '비활성화된 계정입니다. 관리자에게 문의하세요.'}
    const {data:kw,error:ke}=await sb.from('key_wraps').select('*').eq('user_id',uid).single();
    if(ke)throw ke;
    S.dekRaw=await unwrap(pw,kw);S.dek=await importDek(S.dekRaw);
    S.me=await DEC.profiles(p);return true;
  }catch(e){await sb.auth.signOut();S.dek=null;S.dekRaw=null;return '암호 키를 열지 못했습니다. 관리자에게 비밀번호 초기화를 요청하세요.'}
}
async function logout(){
  if(S.chan){sb.removeChannel(S.chan);S.chan=null}
  try{await sb.auth.signOut()}catch{}
  S.dek=null;S.dekRaw=null;S.me=null;['accounts','tasks','meetings','comments'].forEach(k=>S[k].clear());S.loaded=false;closeModal();gate('login');
}

/* ============ 데이터 로드 + 실시간 ============ */
async function loadAll(){
  for(const t of Object.keys(DEC)){
    const rows=await fetchAll(t),m=S[MAPKEY[t]];m.clear();
    for(const r of rows){try{m.set(r.id,await DEC[t](r))}catch{/* 복호화 실패 행은 건너뜀 */}}
  }
  S.lastSync=Date.now();
  const me=S.accounts.get(S.me.id);if(!me||!me.active){toast('계정이 삭제되었거나 비활성화되었습니다.');return logout()}
  S.me=me;
}
let chain=Promise.resolve();
function onChange(t,p){
  chain=chain.then(async()=>{
    const m=S[MAPKEY[t]];
    if(p.eventType==='DELETE'){const id=p.old?.id;if(id)m.delete(id);
      if(t==='tasks'||t==='meetings')for(const[c,v]of S.comments)if(v.target===id)S.comments.delete(c);}
    else{try{m.set(p.new.id,await DEC[t](p.new))}catch{}}
    if(t==='profiles'&&S.me){const me=S.accounts.get(S.me.id);if(!me||!me.active){toast('계정이 삭제되었거나 비활성화되었습니다.');return logout()}S.me=me}
    render();
  });
}
async function startApp(){
  renderShell();
  try{await loadAll()}catch(e){toast('데이터를 불러오지 못했습니다: '+e.message);return}
  if(!S.me)return;
  S.loaded=true;renderShell();
  S.chan=sb.channel('tf-'+rnd(6));
  ['profiles','tasks','meetings','comments'].forEach(t=>S.chan.on('postgres_changes',{event:'*',schema:'public',table:t},p=>onChange(t,p)));
  S.chan.subscribe();
}
// 탭으로 돌아올 때 1분 이상 지났으면 전체 동기화(실시간 연결이 끊겼을 경우 대비)
document.addEventListener('visibilitychange',async()=>{
  if(document.visibilityState==='visible'&&S.me&&Date.now()-S.lastSync>60000){try{await loadAll();render()}catch{}}
});
async function safe(fn_,ok){
  try{const r=await fn_();if(r&&r.error)throw r.error;if(ok)toast(ok);return r}
  catch(e){const msg=e.code==='42501'||/row-level security/i.test(e.message||'')?'권한이 없는 작업입니다.':(e.message||'처리하지 못했습니다');toast(msg);throw e}
}
const upsertLocal=async(t,row)=>{S[MAPKEY[t]].set(row.id,await DEC[t](row));render()};

/* ============ 공통 렌더 ============ */
function renderShell(){
  const tabs=[['sched','잡스케줄러'],['report','업무 Report'],['meet','회의록 로그']];if(isAdmin())tabs.push(['admin','관리자']);
  if(S.view==='admin'&&!isAdmin())S.view='sched';
  $('#app').innerHTML=`<header class="top"><div class="wrap">
    <div class="brand"><b>닥터빌 TF 워크로그</b><span>ENCRYPTED · SUPABASE</span></div>
    <nav class="tabs" aria-label="메뉴">${tabs.map(([k,l])=>`<button class="tab" data-tab="${k}" aria-current="${S.view===k}">${l}</button>`).join('')}</nav>
    <div class="who"><span class="name">${esc(S.me.name)}</span><span class="role">${isAdmin()?'관리자':'사용자'}</span>
      <button class="lbtn" id="bPw">비밀번호 변경</button><button class="lbtn" id="bOut">로그아웃</button></div>
  </div></header><main class="wrap" id="view"></main>`;
  document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>{S.view=b.dataset.tab;renderShell()});
  $('#bOut').onclick=logout;$('#bPw').onclick=modalPassword;
  render();
}
let lastRole=null;
function render(){
  const v=$('#view');if(!v||!S.me)return;
  if(lastRole!==null&&lastRole!==S.me.role){lastRole=S.me.role;return renderShell()}lastRole=S.me.role;
  if(!S.loaded){v.innerHTML=`<div class="empty">데이터를 불러와 복호화하는 중…</div>`;return}
  const ae=document.activeElement,aid=ae&&v.contains(ae)?ae.id:null,ss=ae?.selectionStart,se=ae?.selectionEnd,sy=window.scrollY;
  v.innerHTML=({sched:vSched,report:vReport,meet:vMeet,admin:vAdmin}[S.view]||vSched)();
  bind[S.view]?.();
  if(aid){const el=document.getElementById(aid);if(el){el.focus();try{if(ss!=null)el.setSelectionRange(ss,se)}catch{}}}
  window.scrollTo(0,sy);
}
function toast(m){const t=$('#toast');t.textContent=m;t.hidden=false;clearTimeout(toast._t);toast._t=setTimeout(()=>t.hidden=true,2800)}

/* ============ 잡스케줄러 ============ */
const scoped=()=>[...S.tasks.values()].filter(t=>S.scope==='all'||t.owner===S.me.id);
const isLate=t=>t.status==='todo'&&t.date<todayStr();
function taskRow(t,showOwner){
  const ed=canEditTask(t);
  return `<div class="trow ${t.status==='done'?'isdone':''}">
    <button class="chk" role="checkbox" aria-checked="${t.status==='done'}" aria-label="완료 표시" data-toggle="${esc(t.id)}" ${ed?'':'disabled'}>${t.status==='done'?'✓':''}</button>
    <div style="min-width:0"><button class="ttl" data-edit="${esc(t.id)}">${esc(t.title)}</button>
      <div class="meta"><span class="jid">${esc(t.id)}</span>${t.status==='done'?'<span class="st done">한 일</span>':isLate(t)?'<span class="st late">기한 지남</span>':'<span class="st todo">할 일</span>'}${showOwner?`<span>${esc(nameOf(t.owner))}</span>`:''}${cCount('task',t.id)?`<span>코멘트 ${cCount('task',t.id)}</span>`:''}</div></div></div>`;
}
function vSched(){
  const m=S.month,y=m.getFullYear(),mo=m.getMonth();
  const start=addDays(m,-m.getDay()),cells=[];
  const list=scoped(),byDate={};list.forEach(t=>(byDate[t.date]??=[]).push(t));
  Object.values(byDate).forEach(a=>a.sort((p,q)=>(p.status===q.status?0:p.status==='todo'?-1:1)||p.title.localeCompare(q.title)));
  const today=todayStr();
  for(let i=0;i<42;i++){const d=addDays(start,i),k=ymd(d);if(i>=35&&d.getMonth()!==mo)break;
    const ts=byDate[k]||[];
    cells.push(`<button class="cell ${d.getMonth()!==mo?'out':''} ${k===today?'today':''} ${k===S.sel?'sel':''} ${d.getDay()===0?'sun':d.getDay()===6?'sat':''}" data-day="${k}" aria-label="${k} 업무 ${ts.length}건">
      <span class="dn"><b>${d.getDate()}</b></span>${ts.slice(0,3).map(t=>`<span class="chip ${t.status}">${esc(t.title)}</span>`).join('')}${ts.length>3?`<span class="more">+${ts.length-3}건</span>`:''}</button>`)}
  const inMonth=list.filter(t=>{const d=pYmd(t.date);return d.getFullYear()===y&&d.getMonth()===mo});
  const dayT=byDate[S.sel]||[];
  const late=list.filter(isLate).sort((a,b)=>a.date.localeCompare(b.date));
  const sd=pYmd(S.sel);
  return `<div class="vhead"><h1>잡스케줄러</h1>
    <div class="navg"><button class="iconbtn" data-mon="-1" aria-label="이전 달">‹</button><span class="lbl">${y}년 ${mo+1}월</span><button class="iconbtn" data-mon="1" aria-label="다음 달">›</button></div>
    <button class="btn sm" data-mon="0">오늘</button><span class="sp"></span>
    <div class="seg" role="group" aria-label="보기 범위"><button data-scope="mine" aria-pressed="${S.scope==='mine'}">내 업무</button><button data-scope="all" aria-pressed="${S.scope==='all'}">팀 전체</button></div>
    <button class="btn primary" data-new="1">+ 업무 등록</button></div>
  <div class="sched"><div class="panel" style="overflow:hidden">
      <div class="cal">${DOW.map((d,i)=>`<div class="dow ${i===0?'sun':i===6?'sat':''}">${d}</div>`).join('')}${cells.join('')}</div>
      <div class="legend" style="padding:10px 14px"><span><i style="background:var(--todo)"></i>할 일</span><span><i style="background:var(--done)"></i>한 일</span><span class="mono">${y}.${pad(mo+1)} · 한 일 ${inMonth.filter(t=>t.status==='done').length} · 할 일 ${inMonth.filter(t=>t.status==='todo').length}</span></div>
    </div>
    <div class="stack">
      <div class="panel"><div class="panel-h"><h2>${sd.getMonth()+1}월 ${sd.getDate()}일 (${DOW[sd.getDay()]})</h2><span style="flex:1"></span><button class="btn sm" data-new="${S.sel}">+ 이 날짜에 등록</button></div>
        <div class="panel-b" style="padding-block:4px">${dayT.length?`<div class="tlist">${dayT.map(t=>taskRow(t,S.scope==='all')).join('')}</div>`:`<div class="empty">등록된 업무가 없습니다.<br>할 일이나 한 일을 기록해 보세요.</div>`}</div></div>
      <div class="panel"><div class="panel-h"><h2>기한 지난 할 일</h2><span class="st late">${late.length}</span></div>
        <div class="panel-b" style="padding-block:4px">${late.length?`<div class="tlist">${late.slice(0,8).map(t=>taskRow(t,S.scope==='all').replace('<div class="meta">',`<div class="meta"><span class="mono">${fmtMD(t.date)}</span>`)).join('')}</div>${late.length>8?`<p class="muted" style="font-size:12px">외 ${late.length-8}건</p>`:''}`:`<div class="empty">밀린 할 일이 없습니다.</div>`}</div></div>
    </div></div>`;
}
const taskPayload=t=>({title:t.title,date:t.date,status:t.status,detail:t.detail||'',doneAt:t.doneAt||null});
async function toggleTask(id){
  const t=S.tasks.get(id);if(!t||!canEditTask(t))return;
  const n={...t,status:t.status==='done'?'todo':'done',doneAt:t.status==='done'?null:Date.now()};
  try{const r=await safe(async()=>sb.from('tasks').update({enc:await encJ(taskPayload(n))}).eq('id',id).select().single(),n.status==='done'?'한 일로 옮겼습니다':'할 일로 되돌렸습니다');await upsertLocal('tasks',r.data)}catch{}
}
function bindTaskRows(){
  document.querySelectorAll('[data-toggle]').forEach(b=>b.onclick=()=>toggleTask(b.dataset.toggle));
  document.querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>modalTask(S.tasks.get(b.dataset.edit)));
}
const bind={};
bind.sched=()=>{
  document.querySelectorAll('[data-day]').forEach(b=>b.onclick=()=>{S.sel=b.dataset.day;const d=pYmd(S.sel);if(d.getMonth()!==S.month.getMonth())S.month=new Date(d.getFullYear(),d.getMonth(),1);render()});
  document.querySelectorAll('[data-mon]').forEach(b=>b.onclick=()=>{const n=+b.dataset.mon;if(n===0){const t=new Date();S.month=new Date(t.getFullYear(),t.getMonth(),1);S.sel=todayStr()}else S.month=new Date(S.month.getFullYear(),S.month.getMonth()+n,1);render()});
  document.querySelectorAll('[data-scope]').forEach(b=>b.onclick=()=>{S.scope=b.dataset.scope;render()});
  document.querySelectorAll('[data-new]').forEach(b=>b.onclick=()=>modalTask(null,b.dataset.new==='1'?S.sel:b.dataset.new));
  bindTaskRows();
};

/* ============ 업무 Report ============ */
function period(){
  const a=S.rep.anchor;
  if(S.rep.mode==='week'){const s=weekStart(a),e=addDays(s,6);return{s:ymd(s),e:ymd(e),label:`${s.getFullYear()}.${pad(s.getMonth()+1)}.${pad(s.getDate())} – ${pad(e.getMonth()+1)}.${pad(e.getDate())}`}}
  const s=new Date(a.getFullYear(),a.getMonth(),1),e=new Date(a.getFullYear(),a.getMonth()+1,0);return{s:ymd(s),e:ymd(e),label:`${s.getFullYear()}년 ${s.getMonth()+1}월`};
}
const cList=(type,id)=>[...S.comments.values()].filter(c=>c.type===type&&c.target===id).sort((a,b)=>a.createdAt-b.createdAt);
const cCount=(type,id)=>{let n=0;for(const c of S.comments.values())if(c.type===type&&c.target===id)n++;return n};
function thread(type,id){
  const key=type+':'+id,open=S.open.has(key),cs=cList(type,id);
  const btn=`<button class="cbtn" data-thr="${esc(key)}" aria-expanded="${open}">${open?'코멘트 닫기':`코멘트 ${cs.length?cs.length+'개 보기':'남기기'}`}</button>`;
  if(!open)return btn;
  const fid='c_'+key.replace(/[^A-Za-z0-9]/g,'_');
  return btn+`<div class="thread">${cs.length?cs.map(c=>`<div class="cmt"><div class="h"><b>${esc(c.authorName||nameOf(c.author))}</b><span class="mono">${fmtDT(c.createdAt)}</span>${(c.author===S.me.id||isAdmin())?`<button class="x" data-cdel="${esc(c.id)}" aria-label="코멘트 삭제">삭제</button>`:''}</div><p>${esc(c.text)}</p></div>`).join(''):`<p class="muted" style="margin:0;font-size:12.5px">첫 코멘트를 남겨 주세요. 작성자 이름과 시각이 함께 기록됩니다.</p>`}
    <form class="cform" data-cform="${esc(key)}"><textarea class="input" id="${fid}" rows="2" placeholder="코멘트 입력" data-draft="${esc(key)}">${esc(S.drafts[key]||'')}</textarea><button class="btn primary sm" type="submit">등록</button></form></div>`;
}
function bindThreads(){
  document.querySelectorAll('[data-thr]').forEach(b=>b.onclick=()=>{const k=b.dataset.thr;S.open.has(k)?S.open.delete(k):S.open.add(k);render()});
  document.querySelectorAll('[data-draft]').forEach(t=>t.oninput=()=>S.drafts[t.dataset.draft]=t.value);
  document.querySelectorAll('[data-cform]').forEach(f=>f.onsubmit=async ev=>{ev.preventDefault();const key=f.dataset.cform,txt=(S.drafts[key]||'').trim();if(!txt)return;
    const i=key.indexOf(':'),type=key.slice(0,i),target=key.slice(i+1);
    const row={author:S.me.id,enc:await encJ({text:txt,authorName:S.me.name})};row[type==='task'?'task_id':'meeting_id']=target;
    try{const r=await safe(()=>sb.from('comments').insert(row).select().single(),'코멘트를 등록했습니다');S.drafts[key]='';await upsertLocal('comments',r.data)}catch{}});
  document.querySelectorAll('[data-cdel]').forEach(b=>b.onclick=()=>confirmBox('코멘트를 삭제할까요?','삭제한 코멘트는 되돌릴 수 없습니다.',async()=>{
    await safe(()=>sb.from('comments').delete().eq('id',b.dataset.cdel),'삭제했습니다');S.comments.delete(b.dataset.cdel);render()}));
}
function vReport(){
  const p=period();
  const all=[...S.tasks.values()].filter(t=>t.date>=p.s&&t.date<=p.e&&(S.rep.member==='all'||t.owner===S.rep.member));
  const members=[...new Set(all.map(t=>t.owner))].sort((a,b)=>nameOf(a).localeCompare(nameOf(b),'ko'));
  const accs=[...S.accounts.values()].sort((a,b)=>a.name.localeCompare(b.name,'ko'));
  const done=all.filter(t=>t.status==='done'),todo=all.filter(t=>t.status==='todo');
  const cmts=all.reduce((n,t)=>n+cCount('task',t.id),0);
  const item=t=>`<div class="ritem"><div class="meta" style="margin:0 0 3px"><span class="jid">${esc(t.id)}</span><span class="mono">${fmtMD(t.date)}</span>${isLate(t)?'<span class="st late">기한 지남</span>':''}</div>
    <div class="t">${canEditTask(t)?`<button class="ttl" data-edit="${esc(t.id)}">${esc(t.title)}</button>`:esc(t.title)}</div>${t.detail?`<div class="d">${esc(t.detail)}</div>`:''}${thread('task',t.id)}</div>`;
  const sortD=a=>a.sort((x,y)=>x.date.localeCompare(y.date)||x.title.localeCompare(y.title));
  return `<div class="vhead"><h1>업무 Report</h1>
    <div class="seg" role="group" aria-label="기간 단위"><button data-rmode="week" aria-pressed="${S.rep.mode==='week'}">주간</button><button data-rmode="month" aria-pressed="${S.rep.mode==='month'}">월간</button></div>
    <div class="navg"><button class="iconbtn" data-rnav="-1" aria-label="이전">‹</button><span class="lbl mono">${p.label}</span><button class="iconbtn" data-rnav="1" aria-label="다음">›</button></div>
    <button class="btn sm" data-rnav="0">이번 ${S.rep.mode==='week'?'주':'달'}</button><span class="sp"></span>
    <select class="input" id="rMember" style="width:auto" aria-label="담당자"><option value="all">전체 담당자</option>${accs.map(a=>`<option value="${a.id}" ${S.rep.member===a.id?'selected':''}>${esc(a.name)}</option>`).join('')}</select></div>
  <div class="rsum"><span>한 일 <b>${done.length}</b>건</span><span>할 일 <b>${todo.length}</b>건</span><span>기한 지남 <b>${todo.filter(isLate).length}</b>건</span><span>코멘트 <b>${cmts}</b>개</span></div>
  ${members.length?members.map(mid=>{const mt=all.filter(t=>t.owner===mid),d=sortD(mt.filter(t=>t.status==='done')),tdo=sortD(mt.filter(t=>t.status==='todo'));
    return `<section class="panel member"><div class="panel-h"><h2>${esc(nameOf(mid))}</h2><span class="cnt"><span class="st done">한 일 ${d.length}</span><span class="st todo">할 일 ${tdo.length}</span></span></div>
    <div class="rcols"><div class="rcol"><h3>한 일</h3>${d.length?d.map(item).join(''):'<div class="empty">기록 없음</div>'}</div><div class="rcol"><h3>할 일</h3>${tdo.length?tdo.map(item).join(''):'<div class="empty">기록 없음</div>'}</div></div></section>`}).join('')
  :`<div class="panel"><div class="empty">이 기간에 입력된 업무가 없습니다.<br>잡스케줄러에서 한 일·할 일을 등록하면 이곳에 업무 단위로 정리되고, 항목마다 코멘트를 남길 수 있습니다.</div></div>`}`;
}
bind.report=()=>{
  document.querySelectorAll('[data-rmode]').forEach(b=>b.onclick=()=>{S.rep.mode=b.dataset.rmode;render()});
  document.querySelectorAll('[data-rnav]').forEach(b=>b.onclick=()=>{const n=+b.dataset.rnav,a=S.rep.anchor;S.rep.anchor=n===0?new Date():S.rep.mode==='week'?addDays(a,7*n):new Date(a.getFullYear(),a.getMonth()+n,1);render()});
  $('#rMember').onchange=e=>{S.rep.member=e.target.value;render()};
  bindThreads();bindTaskRows();
};

/* ============ 회의록 로그 ============ */
const MF=[['agenda','안건'],['content','논의 내용'],['decisions','결정 사항'],['actions','후속 조치 (담당 · 기한)']];
function vMeet(){
  const q=S.meetQ.trim().toLowerCase();
  const ms=[...S.meetings.values()].sort((a,b)=>(b.date+(b.time||'')).localeCompare(a.date+(a.time||''))||b.createdAt-a.createdAt)
    .filter(m=>!q||[m.title,m.attendees,m.agenda,m.content,m.decisions,m.actions,m.place].join(' ').toLowerCase().includes(q));
  if(!S.meetSel||!S.meetings.has(S.meetSel))S.meetSel=ms[0]?.id||null;
  const m=S.meetSel?S.meetings.get(S.meetSel):null;
  if(m)S.open.add('meeting:'+m.id);
  const canEd=m&&(isAdmin()||m.author===S.me.id);
  return `<div class="vhead"><h1>회의록 로그</h1><span class="sp"></span><button class="btn primary" id="mNew">+ 회의록 작성</button></div>
  <div class="meet"><div class="panel" style="overflow:hidden"><div class="panel-b" style="border-bottom:1px solid var(--line)"><input class="input" id="mQ" type="search" placeholder="회의명·참석자·내용 검색" value="${esc(S.meetQ)}" aria-label="회의록 검색"></div>
    <div class="mlist">${ms.length?ms.map(x=>`<button class="mitem" data-msel="${esc(x.id)}" aria-current="${x.id===S.meetSel}"><div class="meta" style="margin:0 0 2px"><span class="mono">${fmtMD(x.date)}${x.time?' '+esc(x.time):''}</span>${cCount('meeting',x.id)?`<span>코멘트 ${cCount('meeting',x.id)}</span>`:''}</div><div class="t">${esc(x.title)}</div><div class="meta">${esc(nameOf(x.author))} 작성</div></button>`).join(''):`<div class="empty">${q?'검색 결과가 없습니다.':'아직 회의록이 없습니다.<br>첫 회의록을 작성해 보세요.'}</div>`}</div></div>
    <div class="panel">${m?`<article class="panel-b mdoc" style="padding:20px 22px">
      <div class="meta" style="margin:0 0 6px"><span class="jid">${esc(m.id)}</span><span>${esc(nameOf(m.author))} 작성 · <span class="mono">${fmtDT(m.createdAt)}</span></span>${m.updatedAt-m.createdAt>1000?`<span>수정 <span class="mono">${fmtDT(m.updatedAt)}</span></span>`:''}</div>
      <div style="display:flex;gap:10px;align-items:flex-start;flex-wrap:wrap"><h2 style="flex:1;min-width:0">${esc(m.title)}</h2>${canEd?`<button class="btn sm" id="mEdit">수정</button>`:''}${isAdmin()?`<button class="btn sm danger" id="mDel">삭제</button>`:''}</div>
      <dl class="mgrid"><dt>일시</dt><dd class="mono">${esc(m.date)}${m.time?' '+esc(m.time):''}</dd><dt>장소</dt><dd>${esc(m.place||'—')}</dd><dt>참석자</dt><dd>${esc(m.attendees||'—')}</dd>
      ${MF.map(([k,l])=>`<dt>${l}</dt><dd>${esc(m[k]||'—')}</dd>`).join('')}</dl>
      <div class="secttl">코멘트 <span class="st todo">${cCount('meeting',m.id)}</span></div>${thread('meeting',m.id)}</article>`
      :`<div class="empty" style="padding:60px 20px">왼쪽 목록에서 회의록을 선택하세요.</div>`}</div></div>`;
}
bind.meet=()=>{
  $('#mNew').onclick=()=>modalMeeting(null);
  $('#mQ').oninput=e=>{S.meetQ=e.target.value;render()};
  document.querySelectorAll('[data-msel]').forEach(b=>b.onclick=()=>{S.meetSel=b.dataset.msel;render()});
  const m=S.meetings.get(S.meetSel);
  if($('#mEdit'))$('#mEdit').onclick=()=>modalMeeting(m);
  if($('#mDel'))$('#mDel').onclick=()=>confirmBox('회의록을 삭제할까요?',`‘${m.title}’과 달린 코멘트 ${cCount('meeting',m.id)}개가 함께 삭제됩니다.`,()=>delRow('meetings',m.id,'회의록을 삭제했습니다'));
  bindThreads();
  const tb=document.querySelector(`[data-thr="meeting:${CSS.escape(S.meetSel||'')}"]`);if(tb)tb.hidden=true;
};
async function delRow(t,id,msg){
  await safe(()=>sb.from(t).delete().eq('id',id),msg);
  S[MAPKEY[t]].delete(id);for(const[c,v]of S.comments)if(v.target===id)S.comments.delete(c);
  if(t==='meetings')S.meetSel=null;render();
}

/* ============ 관리자 ============ */
function vAdmin(){
  const accs=[...S.accounts.values()].sort((a,b)=>(a.role===b.role?0:a.role==='admin'?-1:1)||a.name.localeCompare(b.name,'ko'));
  const q=S.admQ.trim().toLowerCase();
  const ts=[...S.tasks.values()].filter(t=>!q||[t.id,t.title,nameOf(t.owner)].join(' ').toLowerCase().includes(q)).sort((a,b)=>b.date.localeCompare(a.date));
  const ms=[...S.meetings.values()].sort((a,b)=>b.date.localeCompare(a.date));
  return `<div class="vhead"><h1>관리자</h1></div><div class="stack">
  <section class="panel" style="overflow:hidden"><div class="panel-h"><h2>계정 관리</h2><span class="muted" style="font-size:12.5px">${accs.length}명</span></div>
    <form class="addrow" id="fAdd" autocomplete="off">
      <div class="field"><label for="na_id">아이디</label><input class="input" id="na_id" required minlength="3" maxlength="30" pattern="[A-Za-z0-9._-]+" title="영문, 숫자, . _ - 만 사용"></div>
      <div class="field"><label for="na_name">이름</label><input class="input" id="na_name" required maxlength="20"></div>
      <div class="field"><label for="na_pw">초기 비밀번호</label><input class="input" id="na_pw" type="text" required minlength="8" autocomplete="off"></div>
      <div class="field"><label for="na_role">권한</label><select class="input" id="na_role"><option value="user">사용자</option><option value="admin">관리자</option></select></div>
      <button class="btn primary" type="submit" id="na_btn">계정 추가</button></form>
    <div class="tblwrap"><table class="tbl"><thead><tr><th>이름</th><th>아이디</th><th>권한</th><th>상태</th><th>생성일</th><th>관리</th></tr></thead><tbody>
    ${accs.map(a=>`<tr><td><b>${esc(a.name)}</b>${a.id===S.me.id?' <span class="muted">(나)</span>':''}</td><td class="mono">${esc(a.username)}</td>
      <td><span class="st ${a.role==='admin'?'todo':''}" style="${a.role==='admin'?'':'background:var(--sunken);color:var(--muted)'}">${a.role==='admin'?'관리자':'사용자'}</span></td>
      <td>${a.active?'<span class="st done">사용 중</span>':'<span class="st late">비활성</span>'}</td><td class="mono muted">${ymd(new Date(a.createdAt))}</td>
      <td><div class="acts">${a.id===S.me.id?'<span class="muted" style="font-size:12px">상단 ‘비밀번호 변경’ 이용</span>':`
        <button class="btn sm" data-arole="${a.id}">${a.role==='admin'?'사용자로 변경':'관리자로 지정'}</button>
        <button class="btn sm" data-apw="${a.id}">비밀번호 초기화</button>
        <button class="btn sm" data-aact="${a.id}">${a.active?'비활성화':'활성화'}</button>
        <button class="btn sm danger" data-adel="${a.id}">삭제</button>`}</div></td></tr>`).join('')}
    </tbody></table></div></section>
  <section class="panel" style="overflow:hidden"><div class="panel-h"><h2>업무ID 관리</h2><span class="muted" style="font-size:12.5px">${S.tasks.size}건</span><span style="flex:1"></span><input class="input" id="admQ" type="search" placeholder="업무ID·제목·담당자 검색" value="${esc(S.admQ)}" style="max-width:260px" aria-label="업무 검색"></div>
    <div class="tblwrap"><table class="tbl"><thead><tr><th>업무ID</th><th>일자</th><th>담당자</th><th>제목</th><th>구분</th><th>코멘트</th><th></th></tr></thead><tbody>
    ${ts.length?ts.slice(0,300).map(t=>`<tr><td class="mono">${esc(t.id)}</td><td class="mono">${esc(t.date)}</td><td>${esc(nameOf(t.owner))}</td><td class="wrap-t">${esc(t.title)}</td><td>${t.status==='done'?'<span class="st done">한 일</span>':'<span class="st todo">할 일</span>'}</td><td class="mono">${cCount('task',t.id)}</td>
      <td><div class="acts"><button class="btn sm" data-edit="${esc(t.id)}">수정</button><button class="btn sm danger" data-tdel="${esc(t.id)}">삭제</button></div></td></tr>`).join(''):`<tr><td colspan="7"><div class="empty">${q?'검색 결과가 없습니다.':'등록된 업무가 없습니다.'}</div></td></tr>`}
    </tbody></table></div>${ts.length>300?`<p class="muted panel-b" style="margin:0;font-size:12px">최근 300건만 표시합니다. 검색으로 좁혀 주세요.</p>`:''}</section>
  <section class="panel" style="overflow:hidden"><div class="panel-h"><h2>회의록 관리</h2><span class="muted" style="font-size:12.5px">${ms.length}건</span></div>
    <div class="tblwrap"><table class="tbl"><thead><tr><th>ID</th><th>일자</th><th>회의명</th><th>작성자</th><th>코멘트</th><th></th></tr></thead><tbody>
    ${ms.length?ms.map(m=>`<tr><td class="mono">${esc(m.id)}</td><td class="mono">${esc(m.date)}</td><td class="wrap-t">${esc(m.title)}</td><td>${esc(nameOf(m.author))}</td><td class="mono">${cCount('meeting',m.id)}</td><td><button class="btn sm danger" data-mdel="${esc(m.id)}">삭제</button></td></tr>`).join(''):`<tr><td colspan="6"><div class="empty">등록된 회의록이 없습니다.</div></td></tr>`}
    </tbody></table></div></section></div>`;
}
async function adminAct(action,payload,ok){try{await fn(action,payload);toast(ok);await loadAll();render()}catch(e){toast(e.message)}}
bind.admin=()=>{
  $('#fAdd').onsubmit=async ev=>{ev.preventDefault();const btn=$('#na_btn');btn.disabled=true;
    const u=$('#na_id').value.trim(),nm=$('#na_name').value.trim(),pw=$('#na_pw').value,role=$('#na_role').value;
    try{await fn('create',{username:u,password:pw,role,name_enc:await encJ({name:nm}),wrap:await wrapFor(pw,S.dekRaw)});
      toast(`${nm} 계정을 만들었습니다. 아이디와 초기 비밀번호를 본인에게 직접 전달하세요.`);ev.target.reset();await loadAll();render()}
    catch(e){toast(e.message);btn.disabled=false}
  };
  $('#admQ').oninput=e=>{S.admQ=e.target.value;render()};
  document.querySelectorAll('[data-arole]').forEach(b=>b.onclick=()=>{const a=S.accounts.get(b.dataset.arole);adminAct('set_role',{user_id:a.id,role:a.role==='admin'?'user':'admin'},'권한을 변경했습니다')});
  document.querySelectorAll('[data-aact]').forEach(b=>b.onclick=()=>{const a=S.accounts.get(b.dataset.aact);adminAct('set_active',{user_id:a.id,active:!a.active},a.active?'비활성화했습니다. 해당 사용자는 로그인할 수 없습니다.':'활성화했습니다')});
  document.querySelectorAll('[data-adel]').forEach(b=>b.onclick=()=>{const a=S.accounts.get(b.dataset.adel);
    confirmBox(`${a.name} 계정을 삭제할까요?`,'로그인 계정이 영구 삭제됩니다. 이 사용자가 남긴 업무·회의록·코멘트는 유지되며 작성자는 ‘삭제된 사용자’로 표시됩니다.',()=>adminAct('delete',{user_id:a.id},'계정을 삭제했습니다'))});
  document.querySelectorAll('[data-apw]').forEach(b=>b.onclick=()=>modalResetPw(S.accounts.get(b.dataset.apw)));
  document.querySelectorAll('[data-tdel]').forEach(b=>b.onclick=()=>{const t=S.tasks.get(b.dataset.tdel);
    confirmBox(`${t.id} 업무를 삭제할까요?`,`‘${t.title}’과 달린 코멘트 ${cCount('task',t.id)}개가 함께 삭제됩니다.`,()=>delRow('tasks',t.id,'업무를 삭제했습니다'))});
  document.querySelectorAll('[data-mdel]').forEach(b=>b.onclick=()=>{const m=S.meetings.get(b.dataset.mdel);
    confirmBox('회의록을 삭제할까요?',`‘${m.title}’과 달린 코멘트 ${cCount('meeting',m.id)}개가 함께 삭제됩니다.`,()=>delRow('meetings',m.id,'회의록을 삭제했습니다'))});
  bindTaskRows();
};

/* ============ 모달 ============ */
function openModal(html,wide){$('#modal').innerHTML=`<div class="scrim" id="scrim"><div class="modal ${wide?'wide':''}" role="dialog" aria-modal="true">${html}</div></div>`;
  $('#scrim').onclick=e=>{if(e.target.id==='scrim')closeModal()};document.querySelectorAll('[data-close]').forEach(b=>b.onclick=closeModal);
  $('#modal').querySelector('input,textarea,select')?.focus()}
function closeModal(){$('#modal').innerHTML=''}
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&$('#scrim'))closeModal()});
function confirmBox(title,msg,fn_){
  openModal(`<div class="mh"><h2>${esc(title)}</h2></div><div class="mb"><p style="margin:0">${esc(msg)}</p></div>
    <div class="mf"><button class="btn" data-close>취소</button><button class="btn primary" id="cfOk" style="background:var(--danger);border-color:var(--danger)">삭제</button></div>`);
  $('#cfOk').onclick=async()=>{$('#cfOk').disabled=true;try{await fn_()}catch{}closeModal()};
}
function modalTask(t,date){
  const isNew=!t,ed=isNew||canEditTask(t);
  const st=t?.status||(date&&date<todayStr()?'done':'todo');
  openModal(`<form id="fTask"><div class="mh"><h2>${isNew?'업무 등록':ed?'업무 수정':'업무 보기'}</h2>${t?`<span class="jid">${esc(t.id)}</span>`:''}</div>
    <div class="mb">
      <div class="field"><label for="tk_title">업무명</label><input class="input" id="tk_title" required maxlength="120" value="${esc(t?.title||'')}" ${ed?'':'readonly'}></div>
      <div class="g2"><div class="field"><label for="tk_date">일자</label><input class="input" id="tk_date" type="date" required value="${esc(t?.date||date||todayStr())}" ${ed?'':'readonly'}></div>
        <div class="field"><label>구분</label><div class="seg" role="radiogroup">${[['todo','할 일'],['done','한 일']].map(([k,l])=>`<button type="button" role="radio" data-st="${k}" aria-pressed="${st===k}" aria-checked="${st===k}" ${ed?'':'disabled'}>${l}</button>`).join('')}</div></div></div>
      <div class="field"><label for="tk_detail">상세 내용</label><textarea class="input" id="tk_detail" rows="5" maxlength="5000" placeholder="진행 내용, 산출물, 협의 대상 등" ${ed?'':'readonly'}>${esc(t?.detail||'')}</textarea></div>
      ${t?`<p class="muted" style="margin:0;font-size:12px">담당 ${esc(nameOf(t.owner))} · 등록 <span class="mono">${fmtDT(t.createdAt)}</span>${t.doneAt?` · 완료 <span class="mono">${fmtDT(t.doneAt)}</span>`:''}</p>`:''}
    </div>
    <div class="mf">${t&&ed?`<button type="button" class="btn danger" id="tkDel">삭제</button>`:''}<span class="sp"></span><button type="button" class="btn" data-close>${ed?'취소':'닫기'}</button>${ed?`<button type="submit" class="btn primary" id="tkSave">${isNew?'등록':'저장'}</button>`:''}</div></form>`);
  let status=st;
  document.querySelectorAll('[data-st]').forEach(b=>b.onclick=()=>{status=b.dataset.st;document.querySelectorAll('[data-st]').forEach(x=>{x.setAttribute('aria-pressed',x===b);x.setAttribute('aria-checked',x===b)})});
  if($('#tkDel'))$('#tkDel').onclick=()=>confirmBox(`${t.id} 업무를 삭제할까요?`,`‘${t.title}’과 달린 코멘트 ${cCount('task',t.id)}개가 함께 삭제됩니다.`,()=>delRow('tasks',t.id,'업무를 삭제했습니다'));
  $('#fTask').onsubmit=async ev=>{ev.preventDefault();if(!ed)return;$('#tkSave').disabled=true;
    const d=$('#tk_date').value;
    const pl={title:$('#tk_title').value.trim(),date:d,status,detail:$('#tk_detail').value.trim(),doneAt:status==='done'?(t?.doneAt||Date.now()):null};
    try{
      const enc=await encJ(pl);
      const r=isNew
        ?await safe(()=>sb.from('tasks').insert({id:'JOB-'+d.replace(/-/g,'')+'-'+rnd(4),owner:S.me.id,enc}).select().single(),'업무를 등록했습니다')
        :await safe(()=>sb.from('tasks').update({enc}).eq('id',t.id).select().single(),'저장했습니다');
      closeModal();
      if(S.view==='sched'){S.sel=d;const x=pYmd(d);S.month=new Date(x.getFullYear(),x.getMonth(),1)}
      await upsertLocal('tasks',r.data);
    }catch{$('#tkSave')&&($('#tkSave').disabled=false)}
  };
}
function modalMeeting(m){
  openModal(`<form id="fMeet"><div class="mh"><h2>${m?'회의록 수정':'회의록 작성'}</h2>${m?`<span class="jid">${esc(m.id)}</span>`:''}</div><div class="mb">
    <div class="field"><label for="mt_title">회의명</label><input class="input" id="mt_title" required maxlength="120" value="${esc(m?.title||'')}" placeholder="예: TF 주간 정례회의"></div>
    <div class="g2"><div class="field"><label for="mt_date">일자</label><input class="input" id="mt_date" type="date" required value="${esc(m?.date||todayStr())}"></div>
      <div class="field"><label for="mt_time">시간</label><input class="input" id="mt_time" type="time" value="${esc(m?.time||'')}"></div></div>
    <div class="g2"><div class="field"><label for="mt_place">장소</label><input class="input" id="mt_place" maxlength="80" value="${esc(m?.place||'')}" placeholder="회의실 / 온라인"></div>
      <div class="field"><label for="mt_att">참석자</label><input class="input" id="mt_att" maxlength="300" value="${esc(m?.attendees||'')}" placeholder="이름을 쉼표로 구분"></div></div>
    ${MF.map(([k,l])=>`<div class="field"><label for="mt_${k}">${l}</label><textarea class="input" id="mt_${k}" rows="${k==='content'?7:3}" maxlength="20000">${esc(m?.[k]||'')}</textarea></div>`).join('')}
  </div><div class="mf"><span class="sp"></span><button type="button" class="btn" data-close>취소</button><button type="submit" class="btn primary" id="mtSave">${m?'저장':'등록'}</button></div></form>`,true);
  $('#fMeet').onsubmit=async ev=>{ev.preventDefault();$('#mtSave').disabled=true;const d=$('#mt_date').value;
    const pl={title:$('#mt_title').value.trim(),date:d,time:$('#mt_time').value,place:$('#mt_place').value.trim(),attendees:$('#mt_att').value.trim()};
    MF.forEach(([k])=>pl[k]=$('#mt_'+k).value.trim());
    try{
      const enc=await encJ(pl);
      const r=m?await safe(()=>sb.from('meetings').update({enc}).eq('id',m.id).select().single(),'저장했습니다')
               :await safe(()=>sb.from('meetings').insert({id:'MTG-'+d.replace(/-/g,'')+'-'+rnd(4),author:S.me.id,enc}).select().single(),'회의록을 등록했습니다');
      S.meetSel=r.data.id;closeModal();await upsertLocal('meetings',r.data);
    }catch{$('#mtSave')&&($('#mtSave').disabled=false)}
  };
}
function modalPassword(){
  openModal(`<form id="fPw"><div class="mh"><h2>비밀번호 변경</h2></div><div class="mb">
    <div class="field"><label for="pw_cur">현재 비밀번호</label><input class="input" id="pw_cur" type="password" required autocomplete="current-password"></div>
    <div class="field"><label for="pw_new">새 비밀번호 (8자 이상)</label><input class="input" id="pw_new" type="password" required minlength="8" autocomplete="new-password"></div>
    <div class="field"><label for="pw_new2">새 비밀번호 확인</label><input class="input" id="pw_new2" type="password" required minlength="8" autocomplete="new-password"></div>
    <div class="err" id="pw_err"></div></div>
    <div class="mf"><span class="sp"></span><button type="button" class="btn" data-close>취소</button><button type="submit" class="btn primary">변경</button></div></form>`);
  $('#fPw').onsubmit=async ev=>{ev.preventDefault();const err=$('#pw_err');err.textContent='';
    if($('#pw_new').value!==$('#pw_new2').value){err.textContent='새 비밀번호가 서로 다릅니다.';return}
    try{const{data:kw}=await sb.from('key_wraps').select('*').eq('user_id',S.me.id).single();await unwrap($('#pw_cur').value,kw)}catch{err.textContent='현재 비밀번호가 올바르지 않습니다.';return}
    try{await fn('self_password',{password:$('#pw_new').value,wrap:await wrapFor($('#pw_new').value,S.dekRaw)});toast('비밀번호를 변경했습니다');closeModal()}catch(e){err.textContent=e.message}
  };
}
function modalResetPw(a){
  openModal(`<form id="fRp"><div class="mh"><h2>${esc(a.name)} 비밀번호 초기화</h2></div><div class="mb">
    <p class="muted" style="margin:0;font-size:13px">새 임시 비밀번호를 정해 본인에게 직접 전달하세요. 로그인 후 ‘비밀번호 변경’으로 바꾸도록 안내해 주세요.</p>
    <div class="field"><label for="rp_pw">임시 비밀번호 (8자 이상)</label><input class="input" id="rp_pw" type="text" required minlength="8" autocomplete="off"></div></div>
    <div class="mf"><span class="sp"></span><button type="button" class="btn" data-close>취소</button><button type="submit" class="btn primary">초기화</button></div></form>`);
  $('#fRp').onsubmit=async ev=>{ev.preventDefault();const pw=$('#rp_pw').value;
    try{await fn('reset_password',{user_id:a.id,password:pw,wrap:await wrapFor(pw,S.dekRaw)});toast('비밀번호를 초기화했습니다');closeModal()}catch(e){toast(e.message)}};
}

boot();
