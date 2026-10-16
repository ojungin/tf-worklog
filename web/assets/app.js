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
async function fetchAll(t){let out=[],from=0;for(;;){const{data,error}=await sb.from(t).select(COLS[t]||'*').range(from,from+999);if(error)throw error;out=out.concat(data);if(data.length<1000)break;from+=1000}return out}
const ST={progress:'진행중',done:'완료',hold:'보류',fail:'실패'},ST_ORDER=['progress','hold','fail','done'];
const normSt=v=>v==='done'?'done':v==='hold'?'hold':v==='fail'?'fail':'progress'; // 구버전 'todo' → 진행중
const stBadge=t=>`<span class="st ${t.status}">${ST[t.status]}</span>`;
const DEC={
  profiles:async r=>({id:r.id,username:r.username,role:r.role,active:r.active,createdAt:Date.parse(r.created_at),name:(await decJ(r.name_enc)).name}),
  tasks:async r=>{const o=await decJ(r.enc);return {...o,status:normSt(o.status),goal:o.goal||'',id:r.id,owner:r.owner,createdAt:Date.parse(r.created_at),updatedAt:Date.parse(r.updated_at)}},
  meetings:async r=>({...await decJ(r.enc),id:r.id,author:r.author,createdAt:Date.parse(r.created_at),updatedAt:Date.parse(r.updated_at)}),
  comments:async r=>({...await decJ(r.enc),id:r.id,type:r.task_id?'task':'meeting',target:r.task_id||r.meeting_id,author:r.author,createdAt:Date.parse(r.created_at)}),
  tf_reports:async r=>({...await decJ(r.enc),id:r.id,createdBy:r.created_by,createdAt:Date.parse(r.created_at),updatedAt:Date.parse(r.updated_at)}),
  tf_report_revisions:r=>({id:r.id,reportId:r.report_id,editor:r.editor,action:r.action,createdAt:Date.parse(r.created_at)}),
};
const MAPKEY={profiles:'accounts',tasks:'tasks',meetings:'meetings',comments:'comments',tf_reports:'reports',tf_report_revisions:'revisions'};
const COLS={tf_report_revisions:'id,report_id,editor,action,created_at'};  // 이력 스냅샷(enc)은 열람할 때만 불러옴

/* ============ 상태 ============ */
const S={dek:null,dekRaw:null,me:null,chan:null,lastSync:0,
  accounts:new Map(),tasks:new Map(),meetings:new Map(),comments:new Map(),reports:new Map(),revisions:new Map(),rSel:null,rEdit:null,rEditBase:null,rPrev:false,aiEnabled:false,
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
      <div><b>최초 관리자 계정 만들기</b><p class="muted" style="margin:4px 0 0;font-size:13px">GitHub Secrets에 등록한 SETUP_TOKEN 값을 입력하세요. 이 계정으로 팀원 계정을 추가합니다.</p></div>
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
  S.dek=null;S.dekRaw=null;S.me=null;['accounts','tasks','meetings','comments','reports','revisions'].forEach(k=>S[k].clear());S.rEdit=null;S.loaded=false;closeModal();gate('login');
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
      if(t==='tasks'||t==='meetings')for(const[c,v]of S.comments)if(v.target===id)S.comments.delete(c);
      if(t==='tf_reports')for(const[k,v]of S.revisions)if(v.reportId===id)S.revisions.delete(k);}
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
  ['profiles','tasks','meetings','comments','tf_reports','tf_report_revisions'].forEach(t=>S.chan.on('postgres_changes',{event:'*',schema:'public',table:t},p=>onChange(t,p)));
  S.chan.subscribe();
  aiStatus().then(()=>{if(S.view==='reports')render()});
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
  const tabs=[['sched','잡스케줄러'],['report','업무 Report'],['meet','회의록 로그'],['reports','보고서']];if(isAdmin())tabs.push(['admin','관리자']);
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
  v.innerHTML=({sched:vSched,report:vReport,meet:vMeet,reports:vReports,admin:vAdmin}[S.view]||vSched)();
  bind[S.view]?.();
  if(aid){const el=document.getElementById(aid);if(el){el.focus();try{if(ss!=null)el.setSelectionRange(ss,se)}catch{}}}
  window.scrollTo(0,sy);
}
function toast(m){const t=$('#toast');t.textContent=m;t.hidden=false;clearTimeout(toast._t);toast._t=setTimeout(()=>t.hidden=true,2800)}

/* ============ 잡스케줄러 ============ */
const scoped=()=>[...S.tasks.values()].filter(t=>S.scope==='all'||t.owner===S.me.id);
const isOpen=t=>t.status==='progress'||t.status==='hold';
const isLate=t=>isOpen(t)&&t.date<todayStr();
function taskRow(t,showOwner){
  const ed=canEditTask(t);
  return `<div class="trow ${t.status==='done'?'isdone':''}">
    <button class="chk" role="checkbox" aria-checked="${t.status==='done'}" aria-label="완료 표시" title="완료 표시 / 진행중으로 되돌리기" data-toggle="${esc(t.id)}" ${ed?'':'disabled'}>${t.status==='done'?'✓':''}</button>
    <div style="min-width:0"><button class="ttl" data-edit="${esc(t.id)}">${esc(t.title)}</button>
      ${t.goal?`<div class="goal">목표 · ${esc(clip(t.goal,70))}</div>`:''}
      <div class="meta"><span class="jid">${esc(t.id)}</span>${stBadge(t)}${isLate(t)?'<span class="st late">완료일 경과</span>':''}${showOwner?`<span>${esc(nameOf(t.owner))}</span>`:''}${cCount('task',t.id)?`<span>코멘트 ${cCount('task',t.id)}</span>`:''}</div></div></div>`;
}
function vSched(){
  const m=S.month,y=m.getFullYear(),mo=m.getMonth();
  const start=addDays(m,-m.getDay()),cells=[];
  const list=scoped(),byDate={};list.forEach(t=>(byDate[t.date]??=[]).push(t));
  Object.values(byDate).forEach(a=>a.sort((p,q)=>(ST_ORDER.indexOf(p.status)-ST_ORDER.indexOf(q.status))||p.title.localeCompare(q.title)));
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
      <div class="legend" style="padding:10px 14px">${ST_ORDER.map(k=>`<span><i class="lg-${k}"></i>${ST[k]} ${inMonth.filter(t=>t.status===k).length}</span>`).join('')}<span class="mono">${y}.${pad(mo+1)} · 완료일 기준</span></div>
    </div>
    <div class="stack">
      <div class="panel"><div class="panel-h"><h2>${sd.getMonth()+1}월 ${sd.getDate()}일 (${DOW[sd.getDay()]})</h2><span style="flex:1"></span><button class="btn sm" data-new="${S.sel}">+ 이 날짜에 등록</button></div>
        <div class="panel-b" style="padding-block:4px">${dayT.length?`<div class="tlist">${dayT.map(t=>taskRow(t,S.scope==='all')).join('')}</div>`:`<div class="empty">등록된 업무가 없습니다.<br>완료일·목표를 정해 업무를 등록하고 진행 과정을 기록해 보세요.</div>`}</div></div>
      <div class="panel"><div class="panel-h"><h2>완료일 경과 업무</h2><span class="st late">${late.length}</span></div>
        <div class="panel-b" style="padding-block:4px">${late.length?`<div class="tlist">${late.slice(0,8).map(t=>taskRow(t,S.scope==='all').replace('<div class="meta">',`<div class="meta"><span class="mono">${fmtMD(t.date)}</span>`)).join('')}</div>${late.length>8?`<p class="muted" style="font-size:12px">외 ${late.length-8}건</p>`:''}`:`<div class="empty">완료일이 지난 진행중·보류 업무가 없습니다.</div>`}</div></div>
    </div></div>`;
}
const taskPayload=t=>({title:t.title,date:t.date,goal:t.goal||'',status:t.status,detail:t.detail||'',doneAt:t.doneAt||null});
async function toggleTask(id){
  const t=S.tasks.get(id);if(!t||!canEditTask(t))return;
  const n={...t,status:t.status==='done'?'progress':'done',doneAt:t.status==='done'?null:Date.now()};
  try{const r=await safe(async()=>sb.from('tasks').update({enc:await encJ(taskPayload(n))}).eq('id',id).select().single(),n.status==='done'?'완료로 표시했습니다':'진행중으로 되돌렸습니다');await upsertLocal('tasks',r.data)}catch{}
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
  const cnt=k=>all.filter(t=>t.status===k).length;
  const cmts=all.reduce((n,t)=>n+cCount('task',t.id),0);
  const item=t=>`<div class="ritem"><div class="meta" style="margin:0 0 3px"><span class="jid">${esc(t.id)}</span><span class="mono">완료일 ${fmtMD(t.date)}</span>${isLate(t)?'<span class="st late">완료일 경과</span>':''}</div>
    <div class="t">${canEditTask(t)?`<button class="ttl" data-edit="${esc(t.id)}">${esc(t.title)}</button>`:esc(t.title)}</div>${t.goal?`<div class="goal">목표 · ${esc(t.goal)}</div>`:''}${t.detail?`<div class="d">${esc(t.detail)}</div>`:''}${thread('task',t.id)}</div>`;
  const sortD=a=>a.sort((x,y)=>x.date.localeCompare(y.date)||x.title.localeCompare(y.title));
  return `<div class="vhead"><h1>업무 Report</h1>
    <div class="seg" role="group" aria-label="기간 단위"><button data-rmode="week" aria-pressed="${S.rep.mode==='week'}">주간</button><button data-rmode="month" aria-pressed="${S.rep.mode==='month'}">월간</button></div>
    <div class="navg"><button class="iconbtn" data-rnav="-1" aria-label="이전">‹</button><span class="lbl mono">${p.label}</span><button class="iconbtn" data-rnav="1" aria-label="다음">›</button></div>
    <button class="btn sm" data-rnav="0">이번 ${S.rep.mode==='week'?'주':'달'}</button><span class="sp"></span>
    <select class="input" id="rMember" style="width:auto" aria-label="담당자"><option value="all">전체 담당자</option>${accs.map(a=>`<option value="${a.id}" ${S.rep.member===a.id?'selected':''}>${esc(a.name)}</option>`).join('')}</select></div>
  <div class="rsum">${['done','progress','hold','fail'].map(k=>`<span>${ST[k]} <b>${cnt(k)}</b>건</span>`).join('')}<span>완료일 경과 <b>${all.filter(isLate).length}</b>건</span><span>코멘트 <b>${cmts}</b>개</span></div>
  ${members.length?members.map(mid=>{const mt=all.filter(t=>t.owner===mid),G={};['progress','done','hold','fail'].forEach(k=>G[k]=sortD(mt.filter(t=>t.status===k)));
    return `<section class="panel member"><div class="panel-h"><h2>${esc(nameOf(mid))}</h2><span class="cnt">${['progress','done','hold','fail'].filter(k=>G[k].length).map(k=>`<span class="st ${k}">${ST[k]} ${G[k].length}</span>`).join('')}</span></div>
    <div class="rcols q4">${['progress','done','hold','fail'].map(k=>`<div class="rcol"><h3>${ST[k]}</h3>${G[k].length?G[k].map(item).join(''):'<div class="empty">기록 없음</div>'}</div>`).join('')}</div></section>`}).join('')
  :`<div class="panel"><div class="empty">이 기간에 입력된 업무가 없습니다.<br>잡스케줄러에서 업무(완료일·목표·진행사항)를 등록하면 이곳에 업무 단위로 정리되고, 항목마다 코멘트를 남길 수 있습니다.</div></div>`}`;
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
  if(t==='tf_reports'){for(const[k,v]of S.revisions)if(v.reportId===id)S.revisions.delete(k);S.rSel=null}
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
    <div class="tblwrap"><table class="tbl"><thead><tr><th>업무ID</th><th>완료일</th><th>담당자</th><th>업무명</th><th>진행사항</th><th>코멘트</th><th></th></tr></thead><tbody>
    ${ts.length?ts.slice(0,300).map(t=>`<tr><td class="mono">${esc(t.id)}</td><td class="mono">${esc(t.date)}</td><td>${esc(nameOf(t.owner))}</td><td class="wrap-t">${esc(t.title)}</td><td>${stBadge(t)}</td><td class="mono">${cCount('task',t.id)}</td>
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


/* ============ 보고서 ============ */
const CIRC='①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳';
const circ=i=>i<20?CIRC[i]:'-';
const md=s=>{const d=pYmd(s);return `${d.getMonth()+1}.${d.getDate()}`};
const ymdDot=s=>s.replace(/-/g,'.');
const korDate=d=>`${d.getFullYear()}년 ${d.getMonth()+1}월 ${d.getDate()}일`;
const clip=(s,n)=>{s=String(s||'').replace(/\s+/g,' ').trim();return s.length>n?s.slice(0,n-1)+'…':s};
const firstLines=(s,n)=>String(s||'').split('\n').map(x=>x.replace(/^\s*(?:[-•·*]+|\d{1,2}[.)](?!\d)|[①-⑳])\s*/,'').trim()).filter(Boolean).slice(0,n);
const newRptId=()=>{const d=new Date();return 'RPT-'+ymd(d).replace(/-/g,'')+'-'+rnd(4)};

// 기간 내 업무·회의록·코멘트를 모아 요약 재료(facts)로 만듦
function collectFacts(s,e,member){
  const inP=t=>t.date>=s&&t.date<=e&&(member==='all'||t.owner===member);
  const tasks=[...S.tasks.values()].filter(inP).sort((a,b)=>a.date.localeCompare(b.date));
  const days=Math.round((pYmd(e)-pYmd(s))/864e5)+1;
  const ne=ymd(addDays(pYmd(e),days));
  const next=[...S.tasks.values()].filter(t=>isOpen(t)&&t.date>e&&t.date<=ne&&(member==='all'||t.owner===member)).sort((a,b)=>a.date.localeCompare(b.date));
  const late=[...S.tasks.values()].filter(t=>isOpen(t)&&t.date<=e&&t.date<todayStr()&&(member==='all'||t.owner===member)).sort((a,b)=>a.date.localeCompare(b.date));
  const meetings=[...S.meetings.values()].filter(m=>m.date>=s&&m.date<=e).sort((a,b)=>(a.date+(a.time||'')).localeCompare(b.date+(b.time||'')));
  const cm=id=>cList('task',id).map(c=>({by:c.authorName||nameOf(c.author),at:fmtDT(c.createdAt),text:c.text}));
  const mcm=id=>cList('meeting',id).map(c=>({by:c.authorName||nameOf(c.author),at:fmtDT(c.createdAt),text:c.text}));
  return {period:{start:s,end:e,days},nextEnd:ne,members:[...new Set(tasks.map(t=>t.owner))].length,
    tasks:tasks.map(t=>({id:t.id,date:t.date,owner:nameOf(t.owner),status:ST[t.status],title:t.title,goal:t.goal||'',detail:t.detail||'',overdue:isLate(t),comments:cm(t.id)})),
    overdue:late.map(t=>({id:t.id,date:t.date,owner:nameOf(t.owner),title:t.title,status:ST[t.status]})),
    nextPlans:next.map(t=>({id:t.id,date:t.date,owner:nameOf(t.owner),title:t.title,goal:t.goal||''})),
    meetings:meetings.map(m=>({id:m.id,date:m.date,time:m.time||'',title:m.title,place:m.place||'',attendees:m.attendees||'',agenda:m.agenda||'',content:m.content||'',decisions:m.decisions||'',actions:m.actions||'',comments:mcm(m.id)}))};
}

// 규칙 기반 초안 (AI 미사용 시)
function draftReport(title,s,e,member){
  const F=collectFacts(s,e,member);
  const done=F.tasks.filter(t=>t.status===ST.done),todo=F.tasks.filter(t=>t.status===ST.progress),hold=F.tasks.filter(t=>t.status===ST.hold),fail=F.tasks.filter(t=>t.status===ST.fail);
  const cmCount=F.tasks.reduce((n,t)=>n+t.comments.length,0);
  const pLabel=`${ymdDot(s)} ~ ${ymdDot(e)}`;
  const byOwner=list=>{const g={};list.forEach(t=>(g[t.owner]??=[]).push(t));return Object.entries(g).sort((a,b)=>a[0].localeCompare(b[0],'ko'))};
  const summary=[];
  summary.push(F.tasks.length?`보고 기간(${pLabel}) TF 업무는 총 ${F.tasks.length}건으로 완료 ${done.length}건, 진행중 ${todo.length}건, 보류 ${hold.length}건, 실패 ${fail.length}건이며 완료일이 지난 미완료 업무는 ${F.overdue.length}건임`:`보고 기간(${pLabel})에 등록된 TF 업무는 없음`);
  if(F.meetings.length){const dec=F.meetings.flatMap(m=>firstLines(m.decisions,2)).slice(0,2);
    summary.push(`회의 ${F.meetings.length}회 진행(${F.meetings.slice(0,3).map(m=>m.title).join(', ')}${F.meetings.length>3?' 등':''})${dec.length?'. 주요 결정은 '+dec.join(', ')+'임':'함'}`);}
  else summary.push('보고 기간에 기록된 회의는 없음');
  if(F.nextPlans.length) summary.push(`차기 주요 계획은 ${F.nextPlans.slice(0,3).map(t=>t.title).join(', ')}${F.nextPlans.length>3?` 외 ${F.nextPlans.length-3}건`:''}이며 ${ymdDot(F.nextEnd)}까지 진행 예정임`);
  if(F.overdue.length) summary.push(`완료일 경과 업무 ${F.overdue.length}건(${F.overdue.slice(0,2).map(t=>t.title).join(', ')}${F.overdue.length>2?' 등':''})은 일정 재조정이 필요함`);
  if(cmCount) summary.push(`업무 코멘트 ${cmCount}건이 기록되었으며 주요 이슈는 3장에 정리함`);

  const sec=[];
  sec.push({title:'1. 보고 개요',body:[`① 보고 기간 : ${pLabel} (${F.period.days}일)`,`② 대상 : ${member==='all'?'TF 전원':nameOf(member)} (업무 등록 인원 ${F.members}명)`,`③ 집계 기준 : 잡스케줄러 업무 일자, 회의록 회의 일자 기준`].join('\n')});
  {const L=[];byOwner(done).forEach(([o,ts],i)=>{L.push(`${i+1}) ${o} (${ts.length}건)`);ts.forEach((t,j)=>{L.push(`${circ(j)} ${t.title} (완료 ${md(t.date)})`);if(t.goal)L.push(`- 목표 : ${clip(firstLines(t.goal,1)[0]||'',90)}`);{const r=firstLines(t.detail,99).pop();if(r)L.push(`- 최근 경과 : ${clip(r,90)}`)}})});
    sec.push({title:'2. 주요 성과',body:L.length?L.join('\n'):'보고 기간에 완료된 업무 없음'});}
  {const L=[];let k=1;
    if(todo.length){L.push(`${k++}) 진행중 업무 (${todo.length}건)`);todo.forEach((t,j)=>{L.push(`${circ(j)} ${t.title} : ${t.owner}, 완료일 ${md(t.date)}${t.overdue?' (경과)':''}`);if(t.goal)L.push(`- 목표 : ${clip(firstLines(t.goal,1)[0]||'',90)}`)})}
    [[hold,'보류'],[fail,'실패']].forEach(([arr,lb])=>{if(arr.length){L.push(`${k++}) ${lb} 업무 (${arr.length}건)`);arr.forEach((t,j)=>{L.push(`${circ(j)} ${t.title} : ${t.owner}, 완료일 ${md(t.date)}`);const r=firstLines(t.detail,99).pop();if(r)L.push(`- 사유·경과 : ${clip(r,90)}`)})}});
    const lateOut=F.overdue.filter(t=>t.date<s);
    if(lateOut.length){L.push(`${k++}) 이전 기간 미완료 업무 (${lateOut.length}건)`);lateOut.forEach((t,j)=>L.push(`${circ(j)} ${t.title} : ${t.owner}, 완료일 ${md(t.date)} (${t.status})`))}
    const withC=F.tasks.filter(t=>t.comments.length);
    if(withC.length){L.push(`${k++}) 코멘트 이슈`);withC.slice(0,10).forEach((t,j)=>{const c=t.comments[t.comments.length-1];L.push(`${circ(j)} ${t.title} : ${clip(c.text,90)} (${c.by})`)})}
    sec.push({title:'3. 진행 현황 및 이슈',body:L.length?L.join('\n'):'특이 이슈 없음'});}
  {const L=[];F.meetings.forEach((m,i)=>{L.push(`${i+1}) ${m.title} (${md(m.date)}${m.attendees?', 참석 : '+clip(m.attendees,40):''})`);
      const d=firstLines(m.decisions,8),a=firstLines(m.actions,8);
      if(!d.length&&!a.length)firstLines(m.content,3).forEach((x,j)=>L.push(`${circ(j)} ${clip(x,100)}`));
      d.forEach((x,j)=>L.push(`${circ(j)} ${clip(x,120)}`));a.forEach(x=>L.push(`- 후속 조치 : ${clip(x,120)}`));});
    sec.push({title:'4. 회의 주요 결정사항',body:L.length?L.join('\n'):'보고 기간에 기록된 회의 없음'});}
  {const L=[];byOwner(F.nextPlans).forEach(([o,ts],i)=>{L.push(`${i+1}) ${o}`);ts.forEach((t,j)=>L.push(`${circ(j)} ${t.title} (${md(t.date)})`))});
    sec.push({title:'5. 향후 계획',body:L.length?L.join('\n'):`${ymdDot(F.nextEnd)}까지 등록된 차기 계획 없음`});}

  const appendix=[];
  if(F.tasks.length)appendix.push({title:'업무 목록',head:['업무ID','완료일','담당','업무명','목표','진행사항'],rows:F.tasks.map(t=>[t.id,ymdDot(t.date),t.owner,t.title,clip(firstLines(t.goal,1)[0]||'',60),t.status+(t.overdue?'(경과)':'')])});
  if(F.meetings.length)appendix.push({title:'회의 목록',head:['일자','회의명','참석자','결정사항'],rows:F.meetings.map(m=>[ymdDot(m.date),m.title,clip(m.attendees,40),clip(firstLines(m.decisions,3).join(' / '),120)])});
  return {v:1,title,period:{s,e},member,dateLine:`보고일 : ${korDate(new Date())}`,metaLine:`보고기간 : ${pLabel} · 대상 : ${member==='all'?'TF 전원':nameOf(member)}`,summary,sections:sec,appendix};
}

// 본문 표기 → HTML
function bodyHtml(text){
  return String(text||'').split('\n').map(l=>{const t=l.trim();if(!t)return '<div class="rb-gap"></div>';
    if(/^\d+\)\s*/.test(t))return `<p class="rb-sub">${esc(t)}</p>`;
    if(/^[①-⑳]/.test(t))return `<p class="rb-num">${esc(t)}</p>`;
    if(/^[-•]\s*/.test(t))return `<p class="rb-bul">${esc(t.replace(/^[-•]\s*/,''))}</p>`;
    if(/^※/.test(t))return `<p class="rb-note">${esc(t)}</p>`;
    return `<p class="rb-p">${esc(t)}</p>`}).join('');
}
function docHtml(r){
  return `<article class="rdoc">
    <h2 class="rd-title">${esc(r.title)}</h2>
    <p class="rd-meta">${esc(r.dateLine||'')}</p><p class="rd-meta">${esc(r.metaLine||'')}</p>
    ${(r.summary||[]).filter(x=>String(x).trim()).length?`<div class="rd-box"><p class="rd-boxh">■ 보고요약</p>${r.summary.filter(x=>String(x).trim()).map((x,i)=>`<p class="rd-sum">${i+1}. ${esc(x)}</p>`).join('')}</div>`:''}
    ${(r.sections||[]).map(s=>`<h3 class="rd-h">${esc(s.title)}</h3>${bodyHtml(s.body)}`).join('')}
    ${(r.appendix||[]).length?`<h3 class="rd-h">■ 참고자료</h3>${r.appendix.map((t,i)=>`<p class="rd-th">${i+1}. ${esc(t.title)}</p><div class="tblwrap"><table class="rd-tbl"><thead><tr>${t.head.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${t.rows.map(row=>`<tr>${row.map(c=>`<td>${esc(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`).join('')}`:''}
  </article>`;
}

// 편집 화면
function editHtml(d){
  const ta=(id,val,rows,ph)=>`<textarea class="input re-ta" id="${id}" rows="${rows}" placeholder="${ph||''}">${esc(val)}</textarea>`;
  return `<div class="rdoc redit">
    <div class="field"><label for="re_title">제목</label><input class="input re-title" id="re_title" value="${esc(d.title)}"></div>
    <div class="g2"><div class="field"><label for="re_date">보고일 줄</label><input class="input" id="re_date" value="${esc(d.dateLine||'')}"></div>
      <div class="field"><label for="re_meta">기간·대상 줄</label><input class="input" id="re_meta" value="${esc(d.metaLine||'')}"></div></div>
    <div class="field"><label for="re_sum">■ 보고요약 (한 줄에 한 항목, 번호는 자동)</label>${ta('re_sum',(d.summary||[]).join('\n'),6)}</div>
    <p class="re-hint">본문 표기 : <b>1) 소제목</b> · <b>① 번호 항목</b> · <b>- 하위 항목</b> · <b>※ 주석</b> · 그 외는 일반 문단</p>
    ${(d.sections||[]).map((s,i)=>`<section class="re-sec"><div class="re-sech"><input class="input re-st" id="re_st_${i}" data-sec="${i}" value="${esc(s.title)}" aria-label="섹션 제목">
      <button class="iconbtn" data-secup="${i}" aria-label="위로" ${i===0?'disabled':''}>↑</button><button class="iconbtn" data-secdn="${i}" aria-label="아래로" ${i===d.sections.length-1?'disabled':''}>↓</button><button class="btn sm danger" data-secdel="${i}">섹션 삭제</button></div>
      ${ta('re_sb_'+i,s.body,Math.min(18,Math.max(4,String(s.body).split('\n').length+1)))}</section>`).join('')}
    <button class="btn sm" id="re_addsec">+ 섹션 추가</button>
    <h3 class="rd-h">■ 참고자료</h3>
    ${(d.appendix||[]).map((t,ti)=>`<section class="re-sec"><div class="re-sech"><input class="input re-st" id="re_tt_${ti}" value="${esc(t.title)}" aria-label="표 제목"><button class="btn sm danger" data-tbldel="${ti}">표 삭제</button></div>
      <div class="tblwrap"><table class="rd-tbl re-tbl"><thead><tr>${t.head.map((h,ci)=>`<th><input class="re-cell" id="re_h_${ti}_${ci}" value="${esc(h)}"></th>`).join('')}<th></th></tr></thead>
      <tbody>${t.rows.map((row,ri)=>`<tr>${row.map((c,ci)=>`<td><input class="re-cell" id="re_c_${ti}_${ri}_${ci}" value="${esc(c)}"></td>`).join('')}<td><button class="x-row" data-rowdel="${ti}:${ri}" aria-label="행 삭제">×</button></td></tr>`).join('')}</tbody></table></div>
      <button class="btn sm" data-rowadd="${ti}">+ 행 추가</button></section>`).join('')}
    <button class="btn sm" id="re_addtbl">+ 표 추가</button>
  </div>`;
}
// 편집 입력값 → S.rEdit 반영
function syncEdit(){
  const d=S.rEdit;if(!d||!$('#re_title'))return;
  d.title=$('#re_title').value;d.dateLine=$('#re_date').value;d.metaLine=$('#re_meta').value;
  d.summary=$('#re_sum').value.split('\n').map(x=>x.replace(/^\s*\d+\.\s*/,'').trim()).filter(Boolean);
  d.sections.forEach((s,i)=>{s.title=$('#re_st_'+i).value;s.body=$('#re_sb_'+i).value});
  d.appendix.forEach((t,ti)=>{t.title=$('#re_tt_'+ti).value;t.head=t.head.map((h,ci)=>$(`#re_h_${ti}_${ci}`).value);t.rows=t.rows.map((row,ri)=>row.map((c,ci)=>$(`#re_c_${ti}_${ri}_${ci}`).value))});
}

function vReports(){
  const list=[...S.reports.values()].sort((a,b)=>b.updatedAt-a.updatedAt);
  if(S.rEdit) return vReportEdit();
  if(!S.rSel||!S.reports.has(S.rSel))S.rSel=list[0]?.id||null;
  const r=S.rSel?S.reports.get(S.rSel):null;
  const revs=r?revList(r.id):[];
  return `<div class="vhead"><h1>보고서</h1><span class="sp"></span>${isAdmin()?'<button class="btn primary" id="rNew">+ 보고서 생성</button>':''}</div>
  <div class="meet"><div class="panel" style="overflow:hidden"><div class="mlist">${list.length?list.map(x=>`<button class="mitem" data-rsel="${esc(x.id)}" aria-current="${x.id===S.rSel}"><div class="meta" style="margin:0 0 2px"><span class="mono">${ymdDot(x.period?.s||'')} ~ ${ymdDot(x.period?.e||'')}</span></div><div class="t">${esc(x.title)}</div><div class="meta">최종 저장 <span class="mono">${fmtDT(x.updatedAt)}</span></div></button>`).join(''):`<div class="empty">${isAdmin()?'아직 보고서가 없습니다.<br>‘보고서 생성’으로 기간을 고르면 업무 Report와 회의록을 모아 초안을 만듭니다.':'아직 생성된 보고서가 없습니다.<br>관리자가 보고서를 만들면 여기에서 열람·수정할 수 있습니다.'}</div>`}</div></div>
    <div>${r?`<div class="rtool"><span class="jid">${esc(r.id)}</span><span class="sp" style="flex:1"></span>
      <button class="btn sm" id="rEdit">수정</button><button class="btn sm" id="rDocx">Word 다운로드</button><button class="btn sm" id="rHist">수정 이력 ${revs.length}</button>${isAdmin()?'<button class="btn sm danger" id="rDel">삭제</button>':''}</div>
      <div class="rpaper">${docHtml(r)}</div>`:`<div class="panel"><div class="empty" style="padding:60px 20px">왼쪽 목록에서 보고서를 선택하세요.</div></div>`}</div></div>`;
}
function vReportEdit(){
  const d=S.rEdit,isNew=!S.reports.has(d.id);
  const ai=isAdmin()?`<button class="btn sm" id="reAI" ${S.aiEnabled?'':'disabled'} title="${S.aiEnabled?'업무·회의록을 Claude AI로 요약해 보고요약과 본문을 다시 작성합니다':'Anthropic API 키를 등록하면 사용할 수 있습니다'}">Claude AI 요약${S.aiEnabled?'':' (준비 중)'}</button>`:'';
  return `<div class="vhead"><h1>${isNew?'보고서 초안':'보고서 수정'}</h1><span class="jid">${esc(d.id)}</span><span class="sp"></span>
    ${ai}<button class="btn sm" id="rePrev">${S.rPrev?'편집으로':'미리보기'}</button><button class="btn" id="reCancel">취소</button><button class="btn primary" id="reSave">${isNew?'보고서 저장':'저장'}</button></div>
    ${!S.aiEnabled&&isAdmin()?'<div class="banner">Claude AI 요약은 Anthropic API 키 등록 후 켜집니다. 지금은 업무·회의록을 규칙에 따라 정리한 초안입니다.</div>':''}
    <div class="rpaper">${S.rPrev?docHtml(d):editHtml(d)}</div>`;
}
const revList=id=>[...S.revisions.values()].filter(v=>v.reportId===id).sort((a,b)=>b.createdAt-a.createdAt);
bind.reports=()=>{
  document.querySelectorAll('[data-rsel]').forEach(b=>b.onclick=()=>{S.rSel=b.dataset.rsel;render()});
  if($('#rNew'))$('#rNew').onclick=modalNewReport;
  const r=S.reports.get(S.rSel);
  if($('#rEdit'))$('#rEdit').onclick=()=>{S.rEdit=JSON.parse(JSON.stringify(stripMeta(r)));S.rEditBase=r.updatedAt;S.rPrev=false;render()};
  if($('#rDocx'))$('#rDocx').onclick=()=>exportDocx(r);
  if($('#rHist'))$('#rHist').onclick=()=>modalHistory(r);
  if($('#rDel'))$('#rDel').onclick=()=>confirmBox('보고서를 삭제할까요?',`‘${r.title}’과 수정 이력이 모두 삭제됩니다.`,()=>delRow('tf_reports',r.id,'보고서를 삭제했습니다'));
  if(!S.rEdit)return;
  const d=S.rEdit;
  document.querySelectorAll('.redit input, .redit textarea').forEach(el=>el.oninput=()=>syncEdit());
  const re=fn=>()=>{syncEdit();fn();render()};
  if($('#re_addsec'))$('#re_addsec').onclick=re(()=>d.sections.push({title:`${d.sections.length+1}. 새 섹션`,body:''}));
  if($('#re_addtbl'))$('#re_addtbl').onclick=re(()=>d.appendix.push({title:'새 표',head:['항목','내용'],rows:[['','']]}));
  document.querySelectorAll('[data-secdel]').forEach(b=>b.onclick=re(()=>d.sections.splice(+b.dataset.secdel,1)));
  document.querySelectorAll('[data-secup]').forEach(b=>b.onclick=re(()=>{const i=+b.dataset.secup;[d.sections[i-1],d.sections[i]]=[d.sections[i],d.sections[i-1]]}));
  document.querySelectorAll('[data-secdn]').forEach(b=>b.onclick=re(()=>{const i=+b.dataset.secdn;[d.sections[i+1],d.sections[i]]=[d.sections[i],d.sections[i+1]]}));
  document.querySelectorAll('[data-tbldel]').forEach(b=>b.onclick=re(()=>d.appendix.splice(+b.dataset.tbldel,1)));
  document.querySelectorAll('[data-rowadd]').forEach(b=>b.onclick=re(()=>{const t=d.appendix[+b.dataset.rowadd];t.rows.push(t.head.map(()=>''))}));
  document.querySelectorAll('[data-rowdel]').forEach(b=>b.onclick=re(()=>{const[ti,ri]=b.dataset.rowdel.split(':').map(Number);d.appendix[ti].rows.splice(ri,1)}));
  $('#rePrev').onclick=()=>{syncEdit();S.rPrev=!S.rPrev;render()};
  $('#reCancel').onclick=()=>{S.rEdit=null;S.rPrev=false;render()};
  $('#reSave').onclick=()=>{syncEdit();saveReport()};
  if($('#reAI'))$('#reAI').onclick=()=>{syncEdit();aiSummarize()};
};
const stripMeta=r=>{const{id,createdBy,createdAt,updatedAt,...c}=r;return{...c,id}};
async function saveReport(force){
  const d=S.rEdit;if(!d.title.trim())return toast('제목을 입력하세요.');
  const exists=S.reports.has(d.id);
  if(exists&&!force){const cur=S.reports.get(d.id);if(cur.updatedAt!==S.rEditBase){
    openModal(`<div class="mh"><h2>다른 사용자가 먼저 저장했습니다</h2></div><div class="mb"><p style="margin:0">편집을 시작한 뒤 <b>${fmtDT(cur.updatedAt)}</b>에 다른 저장이 있었습니다. 지금 내용으로 저장하면 그 수정 내용을 덮어씁니다. 이전 내용은 수정 이력에 남아 있습니다.</p></div>
      <div class="mf"><button class="btn" data-close>취소</button><button class="btn primary" id="ovw">덮어쓰고 저장</button></div>`);
    $('#ovw').onclick=()=>{closeModal();saveReport(true)};return;}}
  const {id,...content}=d;
  try{
    const enc=await encJ(content);
    const r=exists?await safe(()=>sb.from('tf_reports').update({enc}).eq('id',id).select().single(),'저장했습니다. 수정 이력에 기록되었습니다.')
                  :await safe(()=>sb.from('tf_reports').insert({id,created_by:S.me.id,enc}).select().single(),'보고서를 저장했습니다.');
    S.rEdit=null;S.rPrev=false;S.rSel=id;await upsertLocal('tf_reports',r.data);loadRevisions(id);
  }catch{}
}
async function loadRevisions(id){try{const{data}=await sb.from('tf_report_revisions').select('id,report_id,editor,action,created_at').eq('report_id',id);(data||[]).forEach(v=>S.revisions.set(v.id,DEC.tf_report_revisions(v)));render()}catch{}}
function modalNewReport(){
  const t=new Date(),ws=weekStart(t);
  openModal(`<form id="fNR"><div class="mh"><h2>보고서 생성</h2></div><div class="mb">
    <p class="muted" style="margin:0;font-size:13px">선택한 기간의 업무 Report(업무·목표·진행사항·코멘트)와 회의록을 모아 보고서 초안을 만듭니다. 초안은 화면에서 수정한 뒤 저장합니다.</p>
    <div class="field"><label for="nr_title">보고서 제목</label><input class="input" id="nr_title" value="닥터빌 TF 업무 보고의 건" required maxlength="120"></div>
    <div class="field"><label>기간</label><div class="seg" role="group">${[['tw','이번 주'],['lw','지난 주'],['tm','이번 달'],['lm','지난 달']].map(([k,l])=>`<button type="button" data-pq="${k}">${l}</button>`).join('')}</div></div>
    <div class="g2"><div class="field"><label for="nr_s">시작일</label><input class="input" id="nr_s" type="date" value="${ymd(ws)}" required></div>
      <div class="field"><label for="nr_e">종료일</label><input class="input" id="nr_e" type="date" value="${ymd(addDays(ws,6))}" required></div></div>
    <div class="field"><label for="nr_m">대상</label><select class="input" id="nr_m"><option value="all">TF 전원</option>${[...S.accounts.values()].sort((a,b)=>a.name.localeCompare(b.name,'ko')).map(a=>`<option value="${a.id}">${esc(a.name)}</option>`).join('')}</select></div>
    <div class="err" id="nr_err"></div></div>
    <div class="mf"><span class="sp"></span><button type="button" class="btn" data-close>취소</button><button type="submit" class="btn primary">초안 만들기</button></div></form>`);
  document.querySelectorAll('[data-pq]').forEach(b=>b.onclick=()=>{const k=b.dataset.pq,n=new Date();let s,e;
    if(k==='tw'){s=weekStart(n);e=addDays(s,6)}else if(k==='lw'){s=addDays(weekStart(n),-7);e=addDays(s,6)}
    else if(k==='tm'){s=new Date(n.getFullYear(),n.getMonth(),1);e=new Date(n.getFullYear(),n.getMonth()+1,0)}else{s=new Date(n.getFullYear(),n.getMonth()-1,1);e=new Date(n.getFullYear(),n.getMonth(),0)}
    $('#nr_s').value=ymd(s);$('#nr_e').value=ymd(e)});
  $('#fNR').onsubmit=ev=>{ev.preventDefault();const s=$('#nr_s').value,e=$('#nr_e').value;if(s>e){$('#nr_err').textContent='시작일이 종료일보다 늦습니다.';return}
    S.rEdit={id:newRptId(),...draftReport($('#nr_title').value.trim(),s,e,$('#nr_m').value)};S.rPrev=true;S.rEditBase=null;closeModal();render();
    toast('초안을 만들었습니다. 내용을 확인·수정한 뒤 저장하세요.')};
}
async function aiSummarize(){
  const d=S.rEdit,F=collectFacts(d.period.s,d.period.e,d.member||'all');
  const btn=$('#reAI');btn.disabled=true;btn.textContent='Claude AI 요약 중…';
  try{
    const {data,error}=await sb.functions.invoke('ai-report',{body:{action:'summarize',facts:F}});
    if(error){let code='';try{code=(await error.context.json()).error}catch{}throw new Error({ai_not_configured:'API 키가 등록되지 않았습니다.',too_large:'자료가 너무 많습니다. 기간을 줄여 주세요.',admin_only:'관리자만 사용할 수 있습니다.'}[code]||'AI 요약에 실패했습니다'+(code?` (${code})`:''))}
    d.summary=data.result.summary.map(String);d.sections=data.result.sections.map(s=>({title:String(s.title||''),body:String(s.body||'')}));
    S.rPrev=true;render();toast('Claude AI 요약을 반영했습니다. 내용을 확인한 뒤 저장하세요.');
  }catch(e){toast(e.message);render()}
}
async function aiStatus(){try{const{data}=await sb.functions.invoke('ai-report',{body:{action:'status'}});S.aiEnabled=!!data?.enabled}catch{S.aiEnabled=false}}
async function modalHistory(r){
  await loadRevisions(r.id);const revs=revList(r.id);
  openModal(`<div class="mh"><h2>수정 이력</h2><span class="muted" style="font-size:12.5px">${esc(r.title)}</span></div><div class="mb" style="max-height:60vh;overflow:auto">
    <p class="muted" style="margin:0;font-size:12.5px">저장할 때마다 서버가 자동으로 기록합니다. 이력은 보고서 본문과 Word 파일에는 들어가지 않습니다.</p>
    <div class="tblwrap"><table class="tbl"><thead><tr><th>저장 일시</th><th>저장자</th><th>구분</th><th></th></tr></thead><tbody>
    ${revs.map((v,i)=>`<tr><td class="mono">${fmtDT(v.createdAt)}</td><td>${esc(nameOf(v.editor))}</td><td>${v.action==='create'?'최초 생성':'수정'}${i===0?' <span class="st done">현재</span>':''}</td>
      <td><div class="acts"><button class="btn sm" data-rv="${v.id}">보기</button>${isAdmin()&&i>0?`<button class="btn sm" data-rr="${v.id}">이 버전으로 복원</button>`:''}</div></td></tr>`).join('')||'<tr><td colspan="4"><div class="empty">이력이 없습니다.</div></td></tr>'}
    </tbody></table></div><div id="rvView"></div></div>
    <div class="mf"><span class="sp"></span><button class="btn" data-close>닫기</button></div>`,true);
  const snap=async id=>{const{data,error}=await sb.from('tf_report_revisions').select('enc').eq('id',id).single();if(error)throw error;return decJ(data.enc)};
  document.querySelectorAll('[data-rv]').forEach(b=>b.onclick=async()=>{try{const c=await snap(+b.dataset.rv);$('#rvView').innerHTML=`<div class="rpaper" style="margin-top:12px">${docHtml(c)}</div>`}catch{toast('이력을 불러오지 못했습니다.')}});
  document.querySelectorAll('[data-rr]').forEach(b=>b.onclick=async()=>{try{const c=await snap(+b.dataset.rr);closeModal();S.rEdit={...c,id:r.id};S.rEditBase=r.updatedAt;S.rPrev=true;render();toast('선택한 버전을 불러왔습니다. 저장하면 복원됩니다.')}catch{toast('이력을 불러오지 못했습니다.')}});
}

/* ---------- Word(.docx) 출력: 업로드 양식 기준 (A4, 보고요약 회색 박스, 회색 머리글 표) ---------- */
const DOCX_SRC='https://cdn.jsdelivr.net/npm/docx@8.5.0/build/index.iife.js';
const DOCX_SRI='sha384-v5JwXHXYQQRi5zRcJWDssEQsr2vhTpf4uXXDq+4OV6/mtd8zOakGLqBxLpmumXKr';
function loadDocx(){if(window.docx)return Promise.resolve(window.docx);return new Promise((ok,ng)=>{const s=document.createElement('script');s.src=DOCX_SRC;s.integrity=DOCX_SRI;s.crossOrigin='anonymous';s.onload=()=>ok(window.docx);s.onerror=()=>ng(new Error('Word 변환 모듈을 불러오지 못했습니다.'));document.head.appendChild(s)})}
async function exportDocx(r){
  let D;try{toast('Word 파일을 만드는 중…');D=await loadDocx()}catch(e){return toast(e.message)}
  const {Document,Packer,Paragraph,TextRun,Table,TableRow,TableCell,WidthType,AlignmentType,ShadingType,BorderStyle}=D;
  const F='맑은 고딕',G='EDEDED';
  const run=(t,o={})=>new TextRun({text:t,font:F,size:o.size||22,bold:!!o.bold,color:o.color});
  const para=(t,o={})=>new Paragraph({children:[run(t,o)],alignment:o.align,spacing:{after:o.after??80,before:o.before??0,line:300},indent:o.indent});
  const border={style:BorderStyle.SINGLE,size:4,color:'808080'};const borders={top:border,bottom:border,left:border,right:border};
  const kids=[];
  kids.push(para(r.title,{size:28,bold:true,align:AlignmentType.CENTER,after:200}));
  if(r.dateLine)kids.push(para(r.dateLine,{bold:true,align:AlignmentType.RIGHT,after:40}));
  if(r.metaLine)kids.push(para(r.metaLine,{bold:true,align:AlignmentType.RIGHT,after:200}));
  const sums=(r.summary||[]).filter(x=>String(x).trim());
  if(sums.length)kids.push(new Table({width:{size:100,type:WidthType.PERCENTAGE},rows:[new TableRow({children:[new TableCell({borders,shading:{type:ShadingType.CLEAR,color:'auto',fill:G},margins:{top:120,bottom:120,left:160,right:160},
    children:[para('■ 보고요약',{bold:true,after:100}),...sums.map((x,i)=>para(`${i+1}. ${x}`,{after:80,indent:{left:300,hanging:300}}))]})]})]}));
  const bodyParas=text=>String(text||'').split('\n').map(l=>{const t=l.trim();if(!t)return para('',{after:40});
    if(/^\d+\)\s*/.test(t))return para(t,{bold:true,before:120,after:60});
    if(/^[①-⑳]/.test(t))return para(t,{indent:{left:400,hanging:280}});
    if(/^[-•]\s*/.test(t))return para('· '+t.replace(/^[-•]\s*/,''),{indent:{left:700,hanging:200}});
    if(/^※/.test(t))return para(t,{size:17,color:'555555',indent:{left:400}});
    return para(t,{indent:{left:200}})});
  (r.sections||[]).forEach(s=>{kids.push(para(s.title,{bold:true,before:280,after:100}));kids.push(...bodyParas(s.body))});
  if((r.appendix||[]).length){kids.push(para('■ 참고자료',{bold:true,before:320,after:120}));
    r.appendix.forEach((t,i)=>{kids.push(para(`${i+1}. ${t.title}`,{bold:true,before:160,after:80}));
      const cell=(txt,head)=>new TableCell({borders,shading:head?{type:ShadingType.CLEAR,color:'auto',fill:G}:undefined,margins:{top:40,bottom:40,left:80,right:80},
        children:[new Paragraph({alignment:head?AlignmentType.CENTER:undefined,children:[run(String(txt??''),{size:18,bold:head})]})]});
      kids.push(new Table({width:{size:100,type:WidthType.PERCENTAGE},rows:[new TableRow({tableHeader:true,children:t.head.map(h=>cell(h,true))}),...t.rows.map(row=>new TableRow({children:row.map(c=>cell(c,false))}))]}));});}
  const doc=new Document({styles:{default:{document:{run:{font:F,size:22}}}},sections:[{properties:{page:{size:{width:11906,height:16838},margin:{top:1701,bottom:1701,left:1440,right:1440}}},children:kids}]});
  const blob=await Packer.toBlob(doc);
  const name=`${ymd(new Date()).slice(2).replace(/-/g,'')}_${r.title.replace(/[\\/:*?"<>|]/g,'').trim()||'보고서'}.docx`;
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;document.body.appendChild(a);a.click();setTimeout(()=>{URL.revokeObjectURL(a.href);a.remove()},1000);
  toast('Word 파일을 내려받았습니다.');
}

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
  const st=t?.status||'progress';
  openModal(`<form id="fTask"><div class="mh"><h2>${isNew?'업무 등록':ed?'업무 수정':'업무 보기'}</h2>${t?`<span class="jid">${esc(t.id)}</span>`:''}</div>
    <div class="mb">
      <div class="field"><label for="tk_title">업무명</label><input class="input" id="tk_title" required maxlength="120" value="${esc(t?.title||'')}" ${ed?'':'readonly'}></div>
      <div class="g2"><div class="field"><label for="tk_date">완료일</label><input class="input" id="tk_date" type="date" required value="${esc(t?.date||date||todayStr())}" ${ed?'':'readonly'}></div>
        <div class="field"><label>진행사항</label><div class="seg" role="radiogroup" aria-label="진행사항">${['progress','done','hold','fail'].map(k=>[k,ST[k]]).map(([k,l])=>`<button type="button" role="radio" data-st="${k}" aria-pressed="${st===k}" aria-checked="${st===k}" ${ed?'':'disabled'}>${l}</button>`).join('')}</div></div></div>
      <div class="field"><label for="tk_goal">목표</label><textarea class="input" id="tk_goal" rows="2" maxlength="1000" placeholder="완료일까지 달성할 목표 (예: 협력사 3곳 제안서 접수)" ${ed?'':'readonly'}>${esc(t?.goal||'')}</textarea></div>
      <div class="field"><label for="tk_detail">상세 내용</label><textarea class="input" id="tk_detail" rows="6" maxlength="5000" placeholder="진행 과정 중 있었던 일을 날짜와 함께 기록 (예: 10/16 협력사 A 유선 협의 — 단가 재견적 요청)" ${ed?'':'readonly'}>${esc(t?.detail||'')}</textarea></div>
      ${t?`<p class="muted" style="margin:0;font-size:12px">담당 ${esc(nameOf(t.owner))} · 등록 <span class="mono">${fmtDT(t.createdAt)}</span>${t.doneAt?` · 완료 <span class="mono">${fmtDT(t.doneAt)}</span>`:''}</p>`:''}
    </div>
    <div class="mf">${t&&ed?`<button type="button" class="btn danger" id="tkDel">삭제</button>`:''}<span class="sp"></span><button type="button" class="btn" data-close>${ed?'취소':'닫기'}</button>${ed?`<button type="submit" class="btn primary" id="tkSave">${isNew?'등록':'저장'}</button>`:''}</div></form>`);
  let status=st;
  document.querySelectorAll('[data-st]').forEach(b=>b.onclick=()=>{status=b.dataset.st;document.querySelectorAll('[data-st]').forEach(x=>{x.setAttribute('aria-pressed',x===b);x.setAttribute('aria-checked',x===b)})});
  if($('#tkDel'))$('#tkDel').onclick=()=>confirmBox(`${t.id} 업무를 삭제할까요?`,`‘${t.title}’과 달린 코멘트 ${cCount('task',t.id)}개가 함께 삭제됩니다.`,()=>delRow('tasks',t.id,'업무를 삭제했습니다'));
  $('#fTask').onsubmit=async ev=>{ev.preventDefault();if(!ed)return;$('#tkSave').disabled=true;
    const d=$('#tk_date').value;
    const pl={title:$('#tk_title').value.trim(),date:d,goal:$('#tk_goal').value.trim(),status,detail:$('#tk_detail').value.trim(),doneAt:status==='done'?(t?.doneAt||Date.now()):null};
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
