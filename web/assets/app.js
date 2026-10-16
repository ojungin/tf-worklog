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
  tf_goals:async r=>{const o=await decJ(r.enc);return {title:o.title||'',due:o.due||'',status:normSt(o.status),cat:CATS.includes(o.cat)?o.cat:'',id:r.id,owner:r.owner,createdAt:Date.parse(r.created_at),updatedAt:Date.parse(r.updated_at)}},
  tf_works:async r=>{const o=await decJ(r.enc);return {title:o.title||'',due:o.due||'',status:normSt(o.status),id:r.id,goalId:r.goal_id,owner:r.owner,createdAt:Date.parse(r.created_at),updatedAt:Date.parse(r.updated_at)}},
  // 업무 기록(JOB-): 진행 업무(work_id)에 연결된 한 일/할 일. work_id 가 없으면 이전 방식 기록
  tasks:async r=>{const o=await decJ(r.enc),b={id:r.id,owner:r.owner,date:o.date,createdAt:Date.parse(r.created_at),updatedAt:Date.parse(r.updated_at)};
    return r.work_id?{...b,workId:r.work_id,done:o.done||'',todo:o.todo||''}:{...b,workId:null,legacy:true,title:o.title||'',status:normSt(o.status),goal:o.goal||'',done:o.detail||'',todo:''}},
  meetings:async r=>({...await decJ(r.enc),id:r.id,author:r.author,createdAt:Date.parse(r.created_at),updatedAt:Date.parse(r.updated_at)}),
  comments:async r=>({...await decJ(r.enc),id:r.id,type:r.task_id?'task':r.work_id?'mwork':'meeting',target:r.task_id||(r.work_id?r.meeting_id+'|'+r.work_id:r.meeting_id),
    meetingId:r.meeting_id,workId:r.work_id,author:r.author,createdAt:Date.parse(r.created_at),updatedAt:r.updated_at?Date.parse(r.updated_at):null}),
  tf_reports:async r=>({...await decJ(r.enc),id:r.id,createdBy:r.created_by,createdAt:Date.parse(r.created_at),updatedAt:Date.parse(r.updated_at)}),
  tf_report_revisions:r=>({id:r.id,reportId:r.report_id,editor:r.editor,action:r.action,createdAt:Date.parse(r.created_at)}),
};
const MAPKEY={profiles:'accounts',tf_goals:'goals',tf_works:'works',tasks:'tasks',meetings:'meetings',comments:'comments',tf_reports:'reports',tf_report_revisions:'revisions'};
const COLS={tf_report_revisions:'id,report_id,editor,action,created_at'};  // 이력 스냅샷(enc)은 열람할 때만 불러옴

/* ============ 상태 ============ */
const S={dek:null,dekRaw:null,me:null,chan:null,lastSync:0,
  accounts:new Map(),goals:new Map(),works:new Map(),tasks:new Map(),meetings:new Map(),comments:new Map(),reports:new Map(),revisions:new Map(),rSel:null,rEdit:null,rEditBase:null,rPrev:false,aiEnabled:false,
  view:'sched',month:new Date(new Date().getFullYear(),new Date().getMonth(),1),sel:todayStr(),scope:'mine',
  rep:{mode:'week',anchor:new Date(),member:'all'},showDone:false,catF:'',meetAll:false,cEdit:null,logs:null,open:new Set(),drafts:{},meetSel:null,meetQ:'',admQ:'',loaded:false};
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
  S.dek=null;S.dekRaw=null;S.me=null;['accounts','goals','works','tasks','meetings','comments','reports','revisions'].forEach(k=>S[k].clear());S.logs=null;S.rEdit=null;S.loaded=false;closeModal();gate('login');
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
    if((t==='tf_goals'||t==='tf_works')&&p.eventType==='DELETE'){try{await loadAll()}catch{}return render()}
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
  ['profiles','tf_goals','tf_works','tasks','meetings','comments','tf_reports','tf_report_revisions'].forEach(t=>S.chan.on('postgres_changes',{event:'*',schema:'public',table:t},p=>onChange(t,p)));
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

/* ============ 업무 모델 (주요 업무 GOL → 진행 업무 WRK → 업무 기록 JOB) ============ */
const CATS=['매출','회원','콘텐츠','서비스'];
const catBadge=g=>g&&g.cat?`<span class="cat c${CATS.indexOf(g.cat)}">${esc(g.cat)}</span>`:'';
const catSel=(id,cur)=>`<div class="seg" role="radiogroup" aria-label="분류" id="${id}">${CATS.map(c=>`<button type="button" role="radio" data-cat="${c}" aria-pressed="${cur===c}" aria-checked="${cur===c}">${c}</button>`).join('')}</div>`;
function bindCat(id,init){let v=init||'';const box=document.getElementById(id);if(!box)return{get:()=>v};box.querySelectorAll('[data-cat]').forEach(b=>b.onclick=()=>{v=v===b.dataset.cat?'':b.dataset.cat;box.querySelectorAll('[data-cat]').forEach(x=>{const on=x.dataset.cat===v;x.setAttribute('aria-pressed',on);x.setAttribute('aria-checked',on)})});return{get:()=>v}}
const LEG='_legacy',LEG_GOAL={id:LEG,title:'이전 방식 기록 (진행 업무 미지정)',due:'',status:'progress',virtual:true};
const isOpen=x=>x.status==='progress'||x.status==='hold';
const isLate=x=>isOpen(x)&&!!x.due&&x.due<todayStr();
const byDueTitle=(a,b)=>(ST_ORDER.indexOf(a.status)-ST_ORDER.indexOf(b.status))||(a.due||'9').localeCompare(b.due||'9')||String(a.title).localeCompare(String(b.title),'ko');
const legacyWork=r=>({id:r.id,goalId:LEG,title:r.title||'(제목 없음)',due:r.date,status:r.status,owner:r.owner,virtual:true,createdAt:r.createdAt});
const allWorks=()=>{const a=[...S.works.values()];for(const r of S.tasks.values())if(!r.workId)a.push(legacyWork(r));return a};
const workOf=r=>r.workId?S.works.get(r.workId):legacyWork(r);
const goalOf=w=>!w?null:w.goalId===LEG?LEG_GOAL:S.goals.get(w.goalId);
const recKey=r=>r.workId||r.id;
const recsOf=wid=>[...S.tasks.values()].filter(r=>recKey(r)===wid).sort((a,b)=>a.date.localeCompare(b.date)||a.createdAt-b.createdAt);
const worksOf=gid=>[...S.works.values()].filter(w=>w.goalId===gid).sort(byDueTitle);
const newId=(p,d)=>p+'-'+(d||todayStr()).replace(/-/g,'')+'-'+rnd(4);
const canEditRec=r=>isAdmin()||r.owner===S.me.id;
const namePayload=x=>({title:x.title,due:x.due||'',status:x.status});
const segSt=(cur,ed=true)=>`<div class="seg" role="radiogroup" aria-label="진행사항">${['progress','done','hold','fail'].map(k=>`<button type="button" role="radio" data-st="${k}" aria-pressed="${cur===k}" aria-checked="${cur===k}" ${ed?'':'disabled'}>${ST[k]}</button>`).join('')}</div>`;
function bindSeg(init,onSet){let v=init;const set=k=>{v=k;document.querySelectorAll('[data-st]').forEach(x=>{const on=x.dataset.st===k;x.setAttribute('aria-pressed',on);x.setAttribute('aria-checked',on)});onSet&&onSet(k)};
  document.querySelectorAll('[data-st]').forEach(b=>b.onclick=()=>set(b.dataset.st));set(init);return{get:()=>v,set}}
const pathHtml=(w,g)=>`<span class="rpath">${g&&!g.virtual?`<span class="jid">${esc(g.id)}</span>`:''}<span class="gname">${esc(g?.title||'(삭제된 주요 업무)')}</span><span class="sep">›</span>${w&&!w.virtual?`<span class="jid">${esc(w.id)}</span>`:''}<b>${esc(w?.title||'(삭제된 진행 업무)')}</b></span>`;
const rLines=r=>`${r.done?`<div class="rline"><span class="rl done">한 일</span><span>${esc(r.done)}</span></div>`:''}${r.todo?`<div class="rline"><span class="rl todo">할 일</span><span>${esc(r.todo)}</span></div>`:''}`;
// 업무 기록·주요 업무·진행 업무 링크 공통 바인딩
function bindWorkLinks(){
  document.querySelectorAll('[data-rec]').forEach(b=>b.onclick=()=>modalRec(S.tasks.get(b.dataset.rec)));
  document.querySelectorAll('[data-goal]').forEach(b=>b.onclick=()=>modalGoal(S.goals.get(b.dataset.goal)));
  document.querySelectorAll('[data-work]').forEach(b=>b.onclick=()=>modalWork(S.works.get(b.dataset.work)));
  document.querySelectorAll('[data-addwork]').forEach(b=>b.onclick=()=>modalWork(null,b.dataset.addwork));
  document.querySelectorAll('[data-recwork]').forEach(b=>b.onclick=()=>modalRec(null,todayStr(),{workId:b.dataset.recwork}));
}

/* ============ 잡스케줄러 ============ */
const myRec=r=>S.scope==='all'||r.owner===S.me.id;
function recRow(r,showOwner){
  const w=workOf(r),g=goalOf(w),n=cCount('task',r.id);
  return `<div class="trow rec"><div style="min-width:0">
    <div class="rhead">${pathHtml(w,g)}${w?stBadge(w):''}</div>${rLines(r)}
    <div class="meta"><span class="jid">${esc(r.id)}</span><span class="mono">${fmtMD(r.date)}</span>${showOwner?`<span>${esc(nameOf(r.owner))}</span>`:''}${n?`<span>코멘트 ${n}</span>`:''}${r.legacy?'<span class="st late">진행 업무 지정 필요</span>':''}<button class="lnk" data-rec="${esc(r.id)}">${canEditRec(r)?'수정':'보기'}</button></div></div></div>`;
}
function goalTree(){
  const mine=S.scope==='mine';
  const rel=w=>!mine||w.owner===S.me.id||recsOf(w.id).some(r=>r.owner===S.me.id);
  let gs=[...S.goals.values()].filter(g=>!mine||g.owner===S.me.id||worksOf(g.id).some(rel));
  const catN=c=>gs.filter(g=>g.cat===c&&(S.showDone||g.status!=='done')).length;
  if(S.catF)gs=gs.filter(g=>g.cat===S.catF);
  const doneN=gs.filter(g=>g.status==='done').length;
  if(!S.showDone)gs=gs.filter(g=>g.status!=='done');
  gs.sort(byDueTitle);
  const legacy=allWorks().filter(w=>w.virtual&&rel(w));
  const body=gs.map(g=>{const ws=worksOf(g.id).filter(w=>rel(w)||!mine).filter(w=>S.showDone||w.status!=='done');
    return `<div class="gnode"><button class="gtitle" data-goal="${esc(g.id)}">${catBadge(g)}<span class="jid">${esc(g.id)}</span><b>${esc(g.title)}</b></button>
      <div class="meta"><button class="lnk" data-goal="${esc(g.id)}">수정</button>${stBadge(g)}${g.due?`<span class="mono">완료일 ${fmtMD(g.due)}</span>`:''}${isLate(g)?'<span class="st late">완료일 경과</span>':''}<span>${esc(nameOf(g.owner))}</span><button class="lnk" data-addwork="${esc(g.id)}">+ 진행 업무</button></div>
      <div class="wlist">${ws.map(w=>{const rs=recsOf(w.id),last=rs[rs.length-1];return `<div class="wnode"><button class="wbtn" data-work="${esc(w.id)}"><span class="jid">${esc(w.id)}</span><span class="wt">${esc(w.title)}</span></button>${stBadge(w)}${w.due?`<span class="mono muted">~${md(w.due)}</span>`:''}${isLate(w)?'<span class="st late">경과</span>':''}<span class="muted">${rs.length?`기록 ${rs.length}`:'기록 없음'}</span>${rs.length?`<button class="lnk" data-rec="${esc(last.id)}" title="가장 최근 업무 기록을 열어 한 일·할 일을 수정·추가">최근 ${md(last.date)} 기록 수정</button>`:''}<button class="lnk" data-work="${esc(w.id)}" title="진행 업무명·완료일·진행사항 수정, 전체 기록 보기">업무 수정</button><button class="lnk" data-recwork="${esc(w.id)}">+ 기록</button></div>`}).join('')||'<div class="muted" style="font-size:12.5px;padding:4px 0">진행 업무가 없습니다.</div>'}</div></div>`}).join('');
  return `<div class="panel"><div class="panel-h"><h2>주요 업무 현황</h2><span class="muted" style="font-size:12.5px">${gs.length}건</span><span style="flex:1"></span>
    <label class="chkl"><input type="checkbox" id="showDone" ${S.showDone?'checked':''}> 완료 포함${doneN?` (${doneN})`:''}</label><button class="btn sm" data-ngoal="1">+ 주요 업무</button></div>
    <div class="catbar" role="group" aria-label="분류 필터"><button data-catf="" aria-pressed="${!S.catF}">전체</button>${CATS.map(c=>`<button data-catf="${c}" aria-pressed="${S.catF===c}">${c} ${catN(c)}</button>`).join('')}</div>
    <div class="panel-b" style="padding-block:4px">${body||`<div class="empty">등록된 주요 업무가 없습니다.<br>‘+ 주요 업무’로 달성할 목표를 등록하고, 그 아래 진행 업무를 만들어 기록하세요.</div>`}
    ${legacy.length?`<div class="gnode"><div class="gtitle"><b>${esc(LEG_GOAL.title)}</b></div><div class="meta"><span>${legacy.length}건 · 기록을 열어 주요·진행 업무를 지정하면 새 방식으로 바뀝니다</span></div></div>`:''}</div></div>`;
}
function vSched(){
  const m=S.month,y=m.getFullYear(),mo=m.getMonth();
  const start=addDays(m,-m.getDay()),cells=[];
  const recs=[...S.tasks.values()].filter(myRec),byDate={};recs.forEach(r=>(byDate[r.date]??=[]).push(r));
  const mineW=w=>S.scope==='all'||w.owner===S.me.id;
  const dues={};S.works.forEach(w=>{if(w.due&&isOpen(w)&&mineW(w))(dues[w.due]??=[]).push(w)});
  Object.values(byDate).forEach(a=>a.sort((p,q)=>p.createdAt-q.createdAt));
  const today=todayStr();
  for(let i=0;i<42;i++){const d=addDays(start,i),k=ymd(d);if(i>=35&&d.getMonth()!==mo)break;
    const rs=byDate[k]||[],ds=dues[k]||[];
    const chips=[...ds.map(w=>`<span class="chip due" title="진행 업무 완료일">⚑ ${esc(w.title)}</span>`),...rs.map(r=>{const w=workOf(r);return `<span class="chip ${w?.status||'progress'}">${esc(w?.title||'')}</span>`})];
    cells.push(`<button class="cell ${d.getMonth()!==mo?'out':''} ${k===today?'today':''} ${k===S.sel?'sel':''} ${d.getDay()===0?'sun':d.getDay()===6?'sat':''}" data-day="${k}" aria-label="${k} 업무 기록 ${rs.length}건, 완료일 ${ds.length}건">
      <span class="dn"><b>${d.getDate()}</b></span>${chips.slice(0,3).join('')}${chips.length>3?`<span class="more">+${chips.length-3}건</span>`:''}</button>`)}
  const inMonth=recs.filter(r=>{const d=pYmd(r.date);return d.getFullYear()===y&&d.getMonth()===mo});
  const dayR=byDate[S.sel]||[],dayDue=dues[S.sel]||[];
  const lateW=[...S.works.values()].filter(w=>isLate(w)&&mineW(w)).sort((a,b)=>a.due.localeCompare(b.due));
  const lateG=[...S.goals.values()].filter(g=>isLate(g)&&mineW(g)).sort((a,b)=>a.due.localeCompare(b.due));
  const sd=pYmd(S.sel);
  return `<div class="vhead"><h1>잡스케줄러</h1>
    <div class="navg"><button class="iconbtn" data-mon="-1" aria-label="이전 달">‹</button><span class="lbl">${y}년 ${mo+1}월</span><button class="iconbtn" data-mon="1" aria-label="다음 달">›</button></div>
    <button class="btn sm" data-mon="0">오늘</button><span class="sp"></span>
    <div class="seg" role="group" aria-label="보기 범위"><button data-scope="mine" aria-pressed="${S.scope==='mine'}">내 업무</button><button data-scope="all" aria-pressed="${S.scope==='all'}">팀 전체</button></div>
    <button class="btn" data-ngoal="1">+ 주요 업무</button><button class="btn primary" data-new="1">+ 업무 기록</button></div>
  <div class="sched"><div class="stack"><div class="panel" style="overflow:hidden">
      <div class="cal">${DOW.map((d,i)=>`<div class="dow ${i===0?'sun':i===6?'sat':''}">${d}</div>`).join('')}${cells.join('')}</div>
      <div class="legend" style="padding:10px 14px">${ST_ORDER.map(k=>`<span><i class="lg-${k}"></i>${ST[k]}</span>`).join('')}<span><i class="lg-due"></i>진행 업무 완료일</span><span class="mono">${y}.${pad(mo+1)} · 업무 기록 ${inMonth.length}건</span></div>
    </div>${goalTree()}</div>
    <div class="stack">
      <div class="panel"><div class="panel-h"><h2>${sd.getMonth()+1}월 ${sd.getDate()}일 (${DOW[sd.getDay()]})</h2><span style="flex:1"></span><button class="btn sm" data-new="${S.sel}">+ 이 날짜에 기록</button></div>
        <div class="panel-b" style="padding-block:4px">${dayDue.length?`<div class="duebox">${dayDue.map(w=>`<button class="lnk" data-work="${esc(w.id)}">⚑ ${esc(w.title)}</button>`).join('')}<span class="muted">완료일</span></div>`:''}
        ${dayR.length?`<div class="tlist">${dayR.map(r=>recRow(r,S.scope==='all')).join('')}</div>`:`<div class="empty">이 날짜의 업무 기록이 없습니다.<br>주요 업무·진행 업무를 고르고 한 일 / 할 일을 기록하세요.</div>`}</div></div>
      <div class="panel"><div class="panel-h"><h2>완료일 경과 업무</h2><span class="st late">${lateW.length+lateG.length}</span></div>
        <div class="panel-b" style="padding-block:8px">${lateG.length+lateW.length?[...lateG.map(g=>`<div class="lrow"><button class="lnk" data-goal="${esc(g.id)}">${esc(g.title)}</button><span class="muted">주요 업무 · ${fmtMD(g.due)} · ${ST[g.status]}</span></div>`),
          ...lateW.map(w=>`<div class="lrow"><button class="lnk" data-work="${esc(w.id)}">${esc(w.title)}</button><span class="muted">${esc(goalOf(w)?.title||'')} · ${fmtMD(w.due)} · ${ST[w.status]}</span></div>`)].join(''):`<div class="empty">완료일이 지난 진행중·보류 업무가 없습니다.</div>`}</div></div>
    </div></div>`;
}
const bind={};
bind.sched=()=>{
  document.querySelectorAll('[data-day]').forEach(b=>b.onclick=()=>{S.sel=b.dataset.day;const d=pYmd(S.sel);if(d.getMonth()!==S.month.getMonth())S.month=new Date(d.getFullYear(),d.getMonth(),1);render()});
  document.querySelectorAll('[data-mon]').forEach(b=>b.onclick=()=>{const n=+b.dataset.mon;if(n===0){const t=new Date();S.month=new Date(t.getFullYear(),t.getMonth(),1);S.sel=todayStr()}else S.month=new Date(S.month.getFullYear(),S.month.getMonth()+n,1);render()});
  document.querySelectorAll('[data-scope]').forEach(b=>b.onclick=()=>{S.scope=b.dataset.scope;render()});
  document.querySelectorAll('[data-new]').forEach(b=>b.onclick=()=>modalRec(null,b.dataset.new==='1'?S.sel:b.dataset.new));
  document.querySelectorAll('[data-ngoal]').forEach(b=>b.onclick=()=>modalGoal(null));
  $('#showDone').onchange=e=>{S.showDone=e.target.checked;render()};
  document.querySelectorAll('[data-catf]').forEach(b=>b.onclick=()=>{S.catF=b.dataset.catf;render()});
  bindWorkLinks();
};

/* ============ 업무 Report ============ */
function period(){
  const a=S.rep.anchor;
  if(S.rep.mode==='week'){const s=weekStart(a),e=addDays(s,6);return{s:ymd(s),e:ymd(e),label:`${s.getFullYear()}.${pad(s.getMonth()+1)}.${pad(s.getDate())} – ${pad(e.getMonth()+1)}.${pad(e.getDate())}`}}
  const s=new Date(a.getFullYear(),a.getMonth(),1),e=new Date(a.getFullYear(),a.getMonth()+1,0);return{s:ymd(s),e:ymd(e),label:`${s.getFullYear()}년 ${s.getMonth()+1}월`};
}
const cList=(type,id)=>[...S.comments.values()].filter(c=>c.type===type&&c.target===id).sort((a,b)=>a.createdAt-b.createdAt);
const cCount=(type,id)=>{let n=0;for(const c of S.comments.values())if(c.type===type&&c.target===id)n++;return n};
// 회의록에서 남긴 진행 업무 코멘트 (회의 일자가 기간 안인 것)
const mwList=(wid,s,e)=>[...S.comments.values()].filter(c=>{if(c.type!=='mwork'||c.workId!==wid)return false;const m=S.meetings.get(c.meetingId);return m&&(!s||(m.date>=s&&m.date<=e))}).sort((a,b)=>a.createdAt-b.createdAt);
function thread(type,id){
  const key=type+':'+id,open=S.open.has(key),cs=cList(type,id);
  const btn=`<button class="cbtn" data-thr="${esc(key)}" aria-expanded="${open}">${open?'코멘트 닫기':`코멘트 ${cs.length?cs.length+'개 보기':'남기기'}`}</button>`;
  if(!open)return btn;
  const fid='c_'+key.replace(/[^A-Za-z0-9]/g,'_');
  return btn+`<div class="thread">${cs.length?cs.map(c=>{const mine=c.author===S.me.id;
    if(S.cEdit===c.id)return `<div class="cmt"><div class="h"><b>${esc(c.authorName||nameOf(c.author))}</b><span class="mono">${fmtDT(c.createdAt)}</span></div>
      <textarea class="input" id="ce_${c.id}" rows="2">${esc(c.text)}</textarea><div class="acts" style="margin-top:6px"><button class="btn sm" data-cecancel="1">취소</button><button class="btn primary sm" data-cesave="${esc(c.id)}">수정 저장</button></div></div>`;
    return `<div class="cmt"><div class="h"><b>${esc(c.authorName||nameOf(c.author))}</b><span class="mono">${fmtDT(c.createdAt)}</span>${c.updatedAt?`<span class="ed">수정 ${fmtDT(c.updatedAt)}</span>`:''}${mine?`<button class="x" data-cedit="${esc(c.id)}">수정</button>`:''}${(mine||isAdmin())?`<button class="x" data-cdel="${esc(c.id)}" aria-label="코멘트 삭제">삭제</button>`:''}</div><p>${esc(c.text)}</p></div>`}).join('')
    :`<p class="muted" style="margin:0;font-size:12.5px">첫 코멘트를 남겨 주세요. 작성자 이름과 시각이 기록되고, 작성·수정·삭제 이력은 사용자 로그에 남습니다.</p>`}
    <form class="cform" data-cform="${esc(key)}"><textarea class="input" id="${fid}" rows="2" placeholder="코멘트 입력" data-draft="${esc(key)}">${esc(S.drafts[key]||'')}</textarea><button class="btn primary sm" type="submit">등록</button></form></div>`;
}
function bindThreads(){
  document.querySelectorAll('[data-thr]').forEach(b=>b.onclick=()=>{const k=b.dataset.thr;S.open.has(k)?S.open.delete(k):S.open.add(k);render()});
  document.querySelectorAll('[data-draft]').forEach(t=>t.oninput=()=>S.drafts[t.dataset.draft]=t.value);
  document.querySelectorAll('[data-cform]').forEach(f=>f.onsubmit=async ev=>{ev.preventDefault();const key=f.dataset.cform,txt=(S.drafts[key]||'').trim();if(!txt)return;
    const i=key.indexOf(':'),type=key.slice(0,i),target=key.slice(i+1);
    const row={author:S.me.id,enc:await encJ({text:txt,authorName:S.me.name})};
    if(type==='task')row.task_id=target;else if(type==='mwork'){const[mid,wid]=target.split('|');row.meeting_id=mid;row.work_id=wid}else row.meeting_id=target;
    try{const r=await safe(()=>sb.from('comments').insert(row).select().single(),'코멘트를 등록했습니다');S.drafts[key]='';await upsertLocal('comments',r.data)}catch{}});
  document.querySelectorAll('[data-cedit]').forEach(b=>b.onclick=()=>{S.cEdit=b.dataset.cedit;render();$('#ce_'+S.cEdit)?.focus()});
  document.querySelectorAll('[data-cecancel]').forEach(b=>b.onclick=()=>{S.cEdit=null;render()});
  document.querySelectorAll('[data-cesave]').forEach(b=>b.onclick=async()=>{const c=S.comments.get(b.dataset.cesave),txt=$('#ce_'+c.id).value.trim();if(!txt)return;
    if(txt===c.text){S.cEdit=null;return render()}
    try{const r=await safe(async()=>sb.from('comments').update({enc:await encJ({text:txt,authorName:c.authorName||S.me.name})}).eq('id',c.id).select().single(),'코멘트를 수정했습니다. 이전 내용은 사용자 로그에 남습니다.');S.cEdit=null;await upsertLocal('comments',r.data)}catch{}});
  document.querySelectorAll('[data-cdel]').forEach(b=>b.onclick=()=>confirmBox('코멘트를 삭제할까요?','화면에서는 삭제되며, 삭제 기록과 내용은 사용자 로그에 남습니다.',async()=>{
    await safe(()=>sb.from('comments').delete().eq('id',b.dataset.cdel),'삭제했습니다');S.comments.delete(b.dataset.cdel);render()}));
}
// 기간 집계: 기록이 있거나 완료일이 기간 안인 진행 업무를 주요 업무별로 묶음
function periodSet(s,e,member){
  const recs=[...S.tasks.values()].filter(r=>r.date>=s&&r.date<=e&&(member==='all'||r.owner===member));
  const ids=new Set(recs.map(recKey));
  const works=allWorks().filter(w=>ids.has(w.id)||(w.due&&w.due>=s&&w.due<=e&&(member==='all'||w.owner===member)));
  const gmap=new Map();
  works.forEach(w=>{const g=goalOf(w)||{id:'_none',title:'(삭제된 주요 업무)',status:'progress',due:'',virtual:true};if(!gmap.has(g.id))gmap.set(g.id,{g,works:[]});gmap.get(g.id).works.push(w)});
  const groups=[...gmap.values()].sort((a,b)=>((a.g.virtual?1:0)-(b.g.virtual?1:0))||byDueTitle(a.g,b.g));
  groups.forEach(x=>x.works.sort(byDueTitle));
  const recsBy=wid=>recs.filter(r=>recKey(r)===wid).sort((a,b)=>a.date.localeCompare(b.date)||a.createdAt-b.createdAt);
  return {recs,works,groups,recsBy};
}
function vReport(){
  const p=period(),PS=periodSet(p.s,p.e,S.rep.member);
  const accs=[...S.accounts.values()].sort((a,b)=>a.name.localeCompare(b.name,'ko'));
  const cnt=k=>PS.works.filter(w=>w.status===k).length;
  const cmts=PS.recs.reduce((n,r)=>n+cCount('task',r.id),0)+PS.works.reduce((n,w)=>n+(w.virtual?0:mwList(w.id,p.s,p.e).length),0);
  const recHtml=r=>`<div class="rrec"><div class="meta" style="margin:0"><span class="mono">${fmtMD(r.date)}</span><span>${esc(nameOf(r.owner))}</span><span class="jid">${esc(r.id)}</span>${canEditRec(r)?`<button class="lnk" data-rec="${esc(r.id)}">수정</button>`:''}</div>${rLines(r)}${thread('task',r.id)}</div>`;
  const workHtml=w=>{const rs=PS.recsBy(w.id),mc=w.virtual?[]:mwList(w.id,p.s,p.e);
    return `<div class="ritem wk"><div class="meta" style="margin:0 0 3px">${w.virtual?'':`<span class="jid">${esc(w.id)}</span>`}${stBadge(w)}${w.due?`<span class="mono">완료일 ${fmtMD(w.due)}</span>`:''}${isLate(w)?'<span class="st late">완료일 경과</span>':''}<span>담당 ${esc(nameOf(w.owner))}</span></div>
    <div class="t">${w.virtual?esc(w.title):`<button class="ttl" data-work="${esc(w.id)}">${esc(w.title)}</button>`}</div>
    ${rs.length?rs.map(recHtml).join(''):'<p class="muted" style="font-size:12.5px;margin:6px 0 0">이 기간 기록 없음</p>'}
    ${mc.length?`<div class="mcm"><div class="mcmh">회의 코멘트 ${mc.length}</div>${mc.map(c=>`<p><b>${esc(c.authorName||nameOf(c.author))}</b> <span class="muted">${esc(S.meetings.get(c.meetingId)?.title||'')} · ${fmtDT(c.createdAt)}</span><br>${esc(c.text)}</p>`).join('')}</div>`:''}</div>`};
  return `<div class="vhead"><h1>업무 Report</h1>
    <div class="seg" role="group" aria-label="기간 단위"><button data-rmode="week" aria-pressed="${S.rep.mode==='week'}">주간</button><button data-rmode="month" aria-pressed="${S.rep.mode==='month'}">월간</button></div>
    <div class="navg"><button class="iconbtn" data-rnav="-1" aria-label="이전">‹</button><span class="lbl mono">${p.label}</span><button class="iconbtn" data-rnav="1" aria-label="다음">›</button></div>
    <button class="btn sm" data-rnav="0">이번 ${S.rep.mode==='week'?'주':'달'}</button><span class="sp"></span>
    <select class="input" id="rMember" style="width:auto" aria-label="담당자"><option value="all">전체 담당자</option>${accs.map(a=>`<option value="${a.id}" ${S.rep.member===a.id?'selected':''}>${esc(a.name)}</option>`).join('')}</select></div>
  <div class="rsum"><span>주요 업무 <b>${PS.groups.filter(x=>!x.g.virtual).length}</b>건</span><span>진행 업무 <b>${PS.works.length}</b>건</span>${['done','progress','hold','fail'].map(k=>`<span>${ST[k]} <b>${cnt(k)}</b></span>`).join('')}<span>업무 기록 <b>${PS.recs.length}</b>건</span><span>완료일 경과 <b>${PS.works.filter(isLate).length}</b></span><span>코멘트 <b>${cmts}</b>개</span></div>
  ${PS.groups.length?PS.groups.map(({g,works})=>`<section class="panel member"><div class="panel-h"><div class="gh2">${catBadge(g)}${g.virtual?'':`<span class="jid">${esc(g.id)}</span>`}<h2>${g.virtual?esc(g.title):`<button class="ttl" data-goal="${esc(g.id)}">${esc(g.title)}</button>`}</h2></div>
      <span class="cnt">${g.virtual?'':stBadge(g)}${g.due?`<span class="mono muted" style="font-size:12px">완료일 ${fmtMD(g.due)}</span>`:''}</span></div>
      <div class="panel-b">${works.map(workHtml).join('')}</div></section>`).join('')
  :`<div class="panel"><div class="empty">이 기간에 기록된 업무가 없습니다.<br>잡스케줄러에서 주요 업무·진행 업무를 고르고 한 일 / 할 일을 기록하면, 이곳에 같은 업무명으로 묶여 정리됩니다.</div></div>`}`;
}
bind.report=()=>{
  document.querySelectorAll('[data-rmode]').forEach(b=>b.onclick=()=>{S.rep.mode=b.dataset.rmode;render()});
  document.querySelectorAll('[data-rnav]').forEach(b=>b.onclick=()=>{const n=+b.dataset.rnav,a=S.rep.anchor;S.rep.anchor=n===0?new Date():S.rep.mode==='week'?addDays(a,7*n):new Date(a.getFullYear(),a.getMonth()+n,1);render()});
  $('#rMember').onchange=e=>{S.rep.member=e.target.value;render()};
  bindThreads();bindWorkLinks();
};

/* ============ 회의록 로그 ============ */
const MF=[['agenda','안건'],['content','논의 내용'],['decisions','결정 사항'],['actions','후속 조치 (담당 · 기한)']];
const meetCmtCount=id=>[...S.comments.values()].filter(c=>c.meetingId===id).length;
// 회의 주간의 업무 Report를 진행 업무 단위로 보여주고, 업무마다 회의 코멘트를 남김
function meetWorkSection(m){
  const s=ymd(weekStart(pYmd(m.date))),e=ymd(addDays(pYmd(s),6)),PS=periodSet(s,e,'all');
  const works=PS.works.filter(w=>!w.virtual);
  if(S.meetAll){const ids=new Set(works.map(w=>w.id));S.works.forEach(w=>{if(isOpen(w)&&!ids.has(w.id))works.push(w)})}
  const gmap=new Map();works.forEach(w=>{const g=goalOf(w);if(!g)return;if(!gmap.has(g.id))gmap.set(g.id,{g,ws:[]});gmap.get(g.id).ws.push(w)});
  const groups=[...gmap.values()].sort((a,b)=>byDueTitle(a.g,b.g));
  const label=`${ymdDot(s)} ~ ${ymdDot(e).slice(5)}`;
  return `<div class="secttl">업무 Report 코멘트 <span class="muted" style="font-weight:400;font-size:12.5px">회의 주간 ${label}</span><span style="flex:1"></span>
    <label class="chkl" style="font-weight:400"><input type="checkbox" id="meetAll" ${S.meetAll?'checked':''}> 진행중·보류 업무 모두 표시</label></div>
    ${groups.length?groups.map(({g,ws})=>`<div class="mgoal"><div class="mgh">${catBadge(g)}<span class="jid">${esc(g.id)}</span><b>${esc(g.title)}</b>${stBadge(g)}</div>
      ${ws.sort(byDueTitle).map(w=>{const rs=PS.recsBy(w.id);return `<div class="mwork"><div class="meta" style="margin:0 0 2px"><span class="jid">${esc(w.id)}</span>${stBadge(w)}${w.due?`<span class="mono">완료일 ${fmtMD(w.due)}</span>`:''}${isLate(w)?'<span class="st late">완료일 경과</span>':''}<span>담당 ${esc(nameOf(w.owner))}</span></div>
        <div class="t"><button class="ttl" data-work="${esc(w.id)}">${esc(w.title)}</button></div>
        ${rs.length?rs.map(r=>`<div class="rrec"><div class="meta" style="margin:0"><span class="mono">${fmtMD(r.date)}</span><span>${esc(nameOf(r.owner))}</span></div>${rLines(r)}</div>`).join(''):'<p class="muted" style="font-size:12.5px;margin:4px 0 0">이 주간 기록 없음</p>'}
        ${thread('mwork',m.id+'|'+w.id)}</div>`}).join('')}</div>`).join('')
    :`<div class="empty">회의 주간(${label})에 기록된 진행 업무가 없습니다.${S.meetAll?'':'<br>‘진행중·보류 업무 모두 표시’를 켜면 진행 중인 업무 전체에 코멘트를 남길 수 있습니다.'}</div>`}`;
}
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
    <div class="mlist">${ms.length?ms.map(x=>{const n=meetCmtCount(x.id);return `<button class="mitem" data-msel="${esc(x.id)}" aria-current="${x.id===S.meetSel}"><div class="meta" style="margin:0 0 2px"><span class="mono">${fmtMD(x.date)}${x.time?' '+esc(x.time):''}</span>${n?`<span>코멘트 ${n}</span>`:''}</div><div class="t">${esc(x.title)}</div><div class="meta">${esc(nameOf(x.author))} 작성</div></button>`}).join(''):`<div class="empty">${q?'검색 결과가 없습니다.':'아직 회의록이 없습니다.<br>첫 회의록을 작성해 보세요.'}</div>`}</div></div>
    <div class="panel">${m?`<article class="panel-b mdoc" style="padding:20px 22px">
      <div class="meta" style="margin:0 0 6px"><span class="jid">${esc(m.id)}</span><span>${esc(nameOf(m.author))} 작성 · <span class="mono">${fmtDT(m.createdAt)}</span></span>${m.updatedAt-m.createdAt>1000?`<span>수정 <span class="mono">${fmtDT(m.updatedAt)}</span></span>`:''}</div>
      <div style="display:flex;gap:10px;align-items:flex-start;flex-wrap:wrap"><h2 style="flex:1;min-width:0">${esc(m.title)}</h2>${canEd?`<button class="btn sm" id="mEdit">수정</button>`:''}${isAdmin()?`<button class="btn sm danger" id="mDel">삭제</button>`:''}</div>
      <dl class="mgrid"><dt>일시</dt><dd class="mono">${esc(m.date)}${m.time?' '+esc(m.time):''}</dd><dt>장소</dt><dd>${esc(m.place||'—')}</dd><dt>참석자</dt><dd>${esc(m.attendees||'—')}</dd>
      ${MF.map(([k,l])=>`<dt>${l}</dt><dd>${esc(m[k]||'—')}</dd>`).join('')}</dl>
      ${meetWorkSection(m)}
      <div class="secttl">회의록 전체 코멘트 <span class="st progress">${cCount('meeting',m.id)}</span></div>${thread('meeting',m.id)}</article>`
      :`<div class="empty" style="padding:60px 20px">왼쪽 목록에서 회의록을 선택하세요.</div>`}</div></div>`;
}
bind.meet=()=>{
  $('#mNew').onclick=()=>modalMeeting(null);
  $('#mQ').oninput=e=>{S.meetQ=e.target.value;render()};
  document.querySelectorAll('[data-msel]').forEach(b=>b.onclick=()=>{S.meetSel=b.dataset.msel;S.cEdit=null;render()});
  const m=S.meetings.get(S.meetSel);
  if($('#mEdit'))$('#mEdit').onclick=()=>modalMeeting(m);
  if($('#mDel'))$('#mDel').onclick=()=>confirmBox('회의록을 삭제할까요?',`‘${m.title}’과 달린 코멘트 ${meetCmtCount(m.id)}개(업무 코멘트 포함)가 함께 삭제됩니다. 삭제 기록은 사용자 로그에 남습니다.`,()=>delRow('meetings',m.id,'회의록을 삭제했습니다'));
  if($('#meetAll'))$('#meetAll').onchange=e=>{S.meetAll=e.target.checked;render()};
  bindThreads();bindWorkLinks();
  const tb=document.querySelector(`[data-thr="meeting:${CSS.escape(S.meetSel||'')}"]`);if(tb)tb.hidden=true;
};
async function delRow(t,id,msg){
  await safe(()=>sb.from(t).delete().eq('id',id),msg);
  if(t==='tf_goals'||t==='tf_works'){try{await loadAll()}catch{}return render()}
  S[MAPKEY[t]].delete(id);for(const[c,v]of S.comments)if(v.target===id||v.meetingId===id)S.comments.delete(c);
  if(t==='tf_reports'){for(const[k,v]of S.revisions)if(v.reportId===id)S.revisions.delete(k);S.rSel=null}
  if(t==='meetings')S.meetSel=null;S.logs=null;render();
}

/* ============ 관리자 ============ */
const ACT={create:'작성',update:'수정',delete:'삭제'};
const logTarget=l=>{const mt=S.meetings.get(l.meeting_id)?.title;
  if(l.task_id){const r=S.tasks.get(l.task_id),w=r&&workOf(r);return `업무 기록 ${l.task_id}${w?' · '+w.title:''}`}
  if(l.work_id)return `회의 ${mt?`‘${mt}’`:l.meeting_id} · 진행 업무 ${S.works.get(l.work_id)?.title||l.work_id}`;
  return `회의록 ${mt?`‘${mt}’`:l.meeting_id||''}`};
async function loadLogs(){
  S.logs='loading';
  try{const{data,error}=await sb.from('tf_comment_log').select('*').order('id',{ascending:false}).limit(500);if(error)throw error;
    const out=[];for(const r of data){let c=null,pv=null;try{c=r.enc?await decJ(r.enc):null}catch{}try{pv=r.prev_enc?await decJ(r.prev_enc):null}catch{}
      out.push({...r,at:Date.parse(r.created_at),text:c?.text??'(복호화 불가)',prev:pv?.text??null})}
    S.logs=out}catch(e){S.logs={error:e.message||'불러오지 못했습니다'}}
  if(S.view==='admin')render();
}
function vAdmin(){
  const accs=[...S.accounts.values()].sort((a,b)=>(a.role===b.role?0:a.role==='admin'?-1:1)||a.name.localeCompare(b.name,'ko'));
  const q=S.admQ.trim().toLowerCase();
  const gs=[...S.goals.values()].sort(byDueTitle);
  const recs=[...S.tasks.values()].filter(r=>{if(!q)return true;const w=workOf(r),g=goalOf(w);return [r.id,r.done,r.todo,w?.title,w?.id,g?.title,g?.id,nameOf(r.owner)].join(' ').toLowerCase().includes(q)}).sort((a,b)=>b.date.localeCompare(a.date)||b.createdAt-a.createdAt);
  const ms=[...S.meetings.values()].sort((a,b)=>b.date.localeCompare(a.date));
  const L=S.logs;
  const logBody=L==null||L==='loading'?`<tr><td colspan="6"><div class="empty">불러오는 중…</div></td></tr>`:L.error?`<tr><td colspan="6"><div class="empty">${esc(L.error)}</div></td></tr>`
    :L.length?L.map(l=>`<tr><td class="mono">${fmtDT(l.at)}</td><td>${esc(nameOf(l.actor))}</td><td><span class="st ${l.action==='delete'?'fail':l.action==='update'?'hold':'done'}">${ACT[l.action]}</span></td><td class="wrap-t">${esc(logTarget(l))}${l.actor!==l.author?`<br><span class="muted" style="font-size:12px">작성자 ${esc(nameOf(l.author))}</span>`:''}</td>
      <td class="wrap-t">${l.action==='update'?`<span class="muted">이전 :</span> ${esc(l.prev??'')}<br><span class="muted">변경 :</span> ${esc(l.text)}`:esc(l.text)}</td></tr>`).join(''):`<tr><td colspan="6"><div class="empty">기록된 코멘트 이력이 없습니다.</div></td></tr>`;
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
  <section class="panel" style="overflow:hidden"><div class="panel-h"><h2>주요 업무 · 진행 업무 ID 관리</h2><span class="muted" style="font-size:12.5px">주요 ${S.goals.size} · 진행 ${S.works.size}</span><span style="flex:1"></span><button class="btn sm" data-ngoal="1">+ 주요 업무</button></div>
    <div class="tblwrap"><table class="tbl"><thead><tr><th>ID</th><th>구분</th><th>업무명</th><th>등록</th><th>완료일</th><th>진행사항</th><th>기록</th><th></th></tr></thead><tbody>
    ${gs.length?gs.map(g=>{const ws=worksOf(g.id);return `<tr class="grow"><td class="mono">${esc(g.id)}</td><td><b>주요</b></td><td class="wrap-t">${catBadge(g)} <b>${esc(g.title)}</b></td><td>${esc(nameOf(g.owner))}</td><td class="mono">${esc(g.due||'')}</td><td>${stBadge(g)}</td><td class="mono">${ws.reduce((n,w)=>n+recsOf(w.id).length,0)}</td>
      <td><div class="acts"><button class="btn sm" data-goal="${esc(g.id)}">수정</button><button class="btn sm danger" data-gdel="${esc(g.id)}">삭제</button></div></td></tr>`
      +ws.map(w=>`<tr><td class="mono" style="padding-left:22px">${esc(w.id)}</td><td>진행</td><td class="wrap-t">${esc(w.title)}</td><td>${esc(nameOf(w.owner))}</td><td class="mono">${esc(w.due||'')}</td><td>${stBadge(w)}</td><td class="mono">${recsOf(w.id).length}</td>
      <td><div class="acts"><button class="btn sm" data-work="${esc(w.id)}">수정</button><button class="btn sm danger" data-wdel="${esc(w.id)}">삭제</button></div></td></tr>`).join('')}).join(''):`<tr><td colspan="8"><div class="empty">등록된 주요 업무가 없습니다.</div></td></tr>`}
    </tbody></table></div></section>
  <section class="panel" style="overflow:hidden"><div class="panel-h"><h2>업무 기록 관리</h2><span class="muted" style="font-size:12.5px">${S.tasks.size}건</span><span style="flex:1"></span><input class="input" id="admQ" type="search" placeholder="ID·업무명·내용·담당자 검색" value="${esc(S.admQ)}" style="max-width:260px" aria-label="업무 기록 검색"></div>
    <div class="tblwrap"><table class="tbl"><thead><tr><th>기록ID</th><th>기록일</th><th>담당</th><th>주요 › 진행 업무</th><th>한 일 / 할 일</th><th>코멘트</th><th></th></tr></thead><tbody>
    ${recs.length?recs.slice(0,300).map(r=>{const w=workOf(r),g=goalOf(w);return `<tr><td class="mono">${esc(r.id)}</td><td class="mono">${esc(r.date)}</td><td>${esc(nameOf(r.owner))}</td><td class="wrap-t"><span class="muted">${esc(g?.title||'')}</span> › ${esc(w?.title||'')}</td>
      <td class="wrap-t">${r.done?'<b>한 일</b> '+esc(clip(r.done,60)):''}${r.done&&r.todo?'<br>':''}${r.todo?'<b>할 일</b> '+esc(clip(r.todo,60)):''}</td><td class="mono">${cCount('task',r.id)}</td>
      <td><div class="acts"><button class="btn sm" data-rec="${esc(r.id)}">수정</button><button class="btn sm danger" data-tdel="${esc(r.id)}">삭제</button></div></td></tr>`}).join(''):`<tr><td colspan="7"><div class="empty">${q?'검색 결과가 없습니다.':'업무 기록이 없습니다.'}</div></td></tr>`}
    </tbody></table></div>${recs.length>300?`<p class="muted panel-b" style="margin:0;font-size:12px">최근 300건만 표시합니다. 검색으로 좁혀 주세요.</p>`:''}</section>
  <section class="panel" style="overflow:hidden"><div class="panel-h"><h2>회의록 관리</h2><span class="muted" style="font-size:12.5px">${ms.length}건</span></div>
    <div class="tblwrap"><table class="tbl"><thead><tr><th>ID</th><th>일자</th><th>회의명</th><th>작성자</th><th>코멘트</th><th></th></tr></thead><tbody>
    ${ms.length?ms.map(m=>`<tr><td class="mono">${esc(m.id)}</td><td class="mono">${esc(m.date)}</td><td class="wrap-t">${esc(m.title)}</td><td>${esc(nameOf(m.author))}</td><td class="mono">${meetCmtCount(m.id)}</td><td><button class="btn sm danger" data-mdel="${esc(m.id)}">삭제</button></td></tr>`).join(''):`<tr><td colspan="6"><div class="empty">등록된 회의록이 없습니다.</div></td></tr>`}
    </tbody></table></div></section>
  <section class="panel" style="overflow:hidden"><div class="panel-h"><h2>코멘트 사용자 로그</h2><span class="muted" style="font-size:12.5px">작성·수정·삭제 이력 · 최근 500건</span><span style="flex:1"></span><button class="btn sm" id="logReload">새로고침</button></div>
    <p class="muted panel-b" style="margin:0;font-size:12.5px;padding-bottom:0">DB가 자동으로 기록하며 화면에서 지우거나 고칠 수 없습니다. 코멘트를 삭제해도 이력과 삭제 전 내용이 남습니다.</p>
    <div class="tblwrap"><table class="tbl"><thead><tr><th>일시</th><th>사용자</th><th>구분</th><th>대상</th><th>내용</th></tr></thead><tbody>${logBody}</tbody></table></div></section></div>`;
}
async function adminAct(action,payload,ok){try{await fn(action,payload);toast(ok);await loadAll();render()}catch(e){toast(e.message)}}
bind.admin=()=>{
  if(S.logs==null)loadLogs();
  $('#logReload').onclick=()=>{loadLogs();render()};
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
  document.querySelectorAll('[data-gdel]').forEach(b=>b.onclick=()=>confirmGoalDel(S.goals.get(b.dataset.gdel)));
  document.querySelectorAll('[data-wdel]').forEach(b=>b.onclick=()=>confirmWorkDel(S.works.get(b.dataset.wdel)));
  document.querySelectorAll('[data-tdel]').forEach(b=>b.onclick=()=>{const r=S.tasks.get(b.dataset.tdel);
    confirmBox(`${r.id} 업무 기록을 삭제할까요?`,`이 기록과 달린 코멘트 ${cCount('task',r.id)}개가 함께 삭제됩니다.`,()=>delRow('tasks',r.id,'업무 기록을 삭제했습니다'))});
  document.querySelectorAll('[data-mdel]').forEach(b=>b.onclick=()=>{const m=S.meetings.get(b.dataset.mdel);
    confirmBox('회의록을 삭제할까요?',`‘${m.title}’과 달린 코멘트 ${meetCmtCount(m.id)}개가 함께 삭제됩니다.`,()=>delRow('meetings',m.id,'회의록을 삭제했습니다'))});
  document.querySelectorAll('[data-ngoal]').forEach(b=>b.onclick=()=>modalGoal(null));
  bindWorkLinks();
};
function confirmGoalDel(g){const ws=worksOf(g.id),n=ws.reduce((k,w)=>k+recsOf(w.id).length,0);
  confirmBox(`${g.id} 주요 업무를 삭제할까요?`,`‘${g.title}’ 아래 진행 업무 ${ws.length}건, 업무 기록 ${n}건과 관련 코멘트가 모두 삭제됩니다. 되돌릴 수 없습니다.`,()=>delRow('tf_goals',g.id,'주요 업무를 삭제했습니다'))}
function confirmWorkDel(w){const n=recsOf(w.id).length;
  confirmBox(`${w.id} 진행 업무를 삭제할까요?`,`‘${w.title}’의 업무 기록 ${n}건과 관련 코멘트(회의 코멘트 포함)가 모두 삭제됩니다. 되돌릴 수 없습니다.`,()=>delRow('tf_works',w.id,'진행 업무를 삭제했습니다'))}



/* ============ 보고서 ============ */
const CIRC='①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳';
const circ=i=>i<20?CIRC[i]:'-';
const md=s=>{const d=pYmd(s);return `${d.getMonth()+1}.${d.getDate()}`};
const ymdDot=s=>s.replace(/-/g,'.');
const korDate=d=>`${d.getFullYear()}년 ${d.getMonth()+1}월 ${d.getDate()}일`;
const clip=(s,n)=>{s=String(s||'').replace(/\s+/g,' ').trim();return s.length>n?s.slice(0,n-1)+'…':s};
const firstLines=(s,n)=>String(s||'').split('\n').map(x=>x.replace(/^\s*(?:[-•·*]+|\d{1,2}[.)](?!\d)|[①-⑳])\s*/,'').trim()).filter(Boolean).slice(0,n);
const newRptId=()=>{const d=new Date();return 'RPT-'+ymd(d).replace(/-/g,'')+'-'+rnd(4)};

// 기간 내 주요 업무 → 진행 업무 → 업무 기록(한 일/할 일)·코멘트, 회의록을 요약 재료(facts)로 만듦
function collectFacts(s,e,member){
  const PS=periodSet(s,e,member);
  const days=Math.round((pYmd(e)-pYmd(s))/864e5)+1,ne=ymd(addDays(pYmd(e),days));
  const mem=w=>member==='all'||w.owner===member;
  const cm=c=>({by:c.authorName||nameOf(c.author),at:fmtDT(c.createdAt),text:c.text});
  const W=w=>({id:w.virtual?'':w.id,title:w.title,owner:nameOf(w.owner),due:w.due||'',status:ST[w.status],overdue:isLate(w),
    records:PS.recsBy(w.id).map(r=>({id:r.id,date:r.date,owner:nameOf(r.owner),done:r.done||'',todo:r.todo||'',comments:cList('task',r.id).map(cm)})),
    meetingComments:w.virtual?[]:mwList(w.id,s,e).map(c=>({meeting:S.meetings.get(c.meetingId)?.title||'',...cm(c)}))});
  const goals=PS.groups.map(x=>({id:x.g.virtual?'':x.g.id,cat:x.g.cat||'',title:x.g.title,due:x.g.due||'',status:x.g.virtual?'':ST[x.g.status],works:x.works.map(W)}));
  const lite=w=>({id:w.virtual?'':w.id,title:w.title,goal:goalOf(w)?.title||'',owner:nameOf(w.owner),due:w.due||'',status:ST[w.status]});
  const overdue=allWorks().filter(w=>isLate(w)&&w.due<=e&&mem(w)).sort((a,b)=>a.due.localeCompare(b.due)).map(lite);
  const nextPlans=allWorks().filter(w=>isOpen(w)&&w.due&&w.due>e&&w.due<=ne&&mem(w)).sort((a,b)=>a.due.localeCompare(b.due))
    .map(w=>{const rs=recsOf(w.id);let todo='';for(let i=rs.length-1;i>=0;i--)if(rs[i].todo){todo=rs[i].todo;break}return {...lite(w),todo}});
  const meetings=[...S.meetings.values()].filter(m=>m.date>=s&&m.date<=e).sort((a,b)=>(a.date+(a.time||'')).localeCompare(b.date+(b.time||'')));
  return {period:{start:s,end:e,days},nextEnd:ne,members:new Set(PS.recs.map(r=>r.owner)).size,goals,overdue,nextPlans,
    meetings:meetings.map(m=>({id:m.id,date:m.date,time:m.time||'',title:m.title,place:m.place||'',attendees:m.attendees||'',agenda:m.agenda||'',content:m.content||'',decisions:m.decisions||'',actions:m.actions||'',
      comments:cList('meeting',m.id).map(cm),
      workComments:[...S.comments.values()].filter(c=>c.type==='mwork'&&c.meetingId===m.id).sort((a,b)=>a.createdAt-b.createdAt).map(c=>{const w=S.works.get(c.workId);return {work:w?.title||'',goal:goalOf(w)?.title||'',...cm(c)}})}))};
}

/* ---------- 실적 (Dashboard_DV 월별 집계 → tf_metrics) ---------- */
async function loadMetrics(){
  try{const{data,error}=await sb.from('tf_metrics').select('data,updated_at').eq('key','dv').maybeSingle();if(error)throw error;
    S.metrics=data?{...data.data,syncedAt:Date.parse(data.updated_at)}:null}catch{S.metrics=null}
  return S.metrics;
}
const nf=(v,d=0)=>v==null||!isFinite(v)?'-':Number(v).toLocaleString('ko-KR',{minimumFractionDigits:d,maximumFractionDigits:d});
const pct=(a,b)=>a==null||b==null||!b?null:(a-b)/Math.abs(b)*100;
const pctTxt=p=>p==null?'-':(p>0?'+':'')+p.toFixed(1)+'%';
const eok=v=>v==null?'-':(v/1e8).toFixed(1)+'억원';
// 연초~보고월 실적 표 + 전년 동기 비교
function buildMetrics(M,e){
  const Y=+e.slice(0,4),Mo=+e.slice(5,7),LY=Y-1,now=new Date(),partial=Y===now.getFullYear()&&Mo===now.getMonth()+1,mk=(y,m)=>`${y}-${pad(m)}`,months=[...Array(Mo)].map((_,i)=>i+1);
  if(!M)return {body:'1) 실적 데이터 없음\n※ Dashboard_DV 실적이 아직 동기화되지 않았음. GitHub Actions ‘Sync DV metrics’ 실행 후 다시 생성 필요',tables:[],sum:null};
  const g=(src,y,m,f)=>{const o=M[src]?.[mk(y,m)];return o==null?null:(f?(o[f]??null):o)};
  const D=[ // [표 라벨, 소스, 필드, 표시 나눗수, 소수, 누계 방식]
    ['매출(백만원)','sales',null,1e6,0,'sum'],
    ['신규 회원(명)','members','new',1,0,'sum'],
    ['누적 회원(명)','members','cum',1,0,'last'],
    ['MAU(명)','activity','mau',1,0,'avg'],
    ['조회수(천회)','activity','views',1e3,0,'sum'],
    ['포인트 사용(백만원)','points','use',1e6,0,'sum'],
    ['포인트 적립(백만원)','points','earn',1e6,0,'sum']];
  const agg=(vals,how)=>{const v=vals.filter(x=>x!=null);if(!v.length)return null;if(how==='sum')return v.reduce((a,b)=>a+b,0);if(how==='avg')return v.reduce((a,b)=>a+b,0)/v.length;
    for(let i=vals.length-1;i>=0;i--)if(vals[i]!=null)return vals[i];return null};
  const R=D.map(([label,src,f,div,dec,how])=>{const cur=months.map(m=>g(src,Y,m,f)),prev=months.map(m=>g(src,LY,m,f));
    // 누계 비교는 양쪽 모두 값이 있는 달만 사용 (진행 중인 달·수집 전 달 왜곡 방지)
    const both=months.map((_,i)=>cur[i]!=null&&prev[i]!=null&&!(partial&&i===Mo-1));const n=both.filter(Boolean).length;
    const ytdC=agg(cur.map((v,i)=>both[i]?v:null),how),ytdP=agg(prev.map((v,i)=>both[i]?v:null),how);
    return {label,div,dec,how,cur,prev,all:agg(cur,how),ytdC:n?ytdC:agg(cur,how),ytdP:n?ytdP:null,n,lastBoth:both.lastIndexOf(true)+1}});
  const cell=(v,r)=>v==null?'-':nf(v/r.div,r.dec);
  const t1={title:`월별 실적 (${Y}년 1~${Mo}월, 전년 동월 비교)`,head:['구분','연도',...months.map(m=>m+'월'),'누계'],rows:[]};
  R.forEach(r=>{const tot=(arr)=>cell(agg(arr,r.how),r);
    t1.rows.push([r.label,String(Y),...r.cur.map(v=>cell(v,r)),tot(r.cur)]);
    t1.rows.push(['',String(LY),...r.prev.map(v=>cell(v,r)),tot(r.prev)]);
    t1.rows.push(['','증감률',...months.map((m,i)=>pctTxt(pct(r.cur[i],r.prev[i]))),pctTxt(r.ytdP==null?null:pct(r.ytdC,r.ytdP))])});
  const t2={title:'전년 동기 대비 (양년 모두 집계된 달 기준 누계)',head:['구분','기준',String(LY),String(Y),'증감','증감률'],rows:R.map(r=>{
    const basis=r.n?`1~${r.lastBoth}월 ${r.how==='sum'?'합계':r.how==='avg'?'월평균':'말'}`:'전년 자료 없음';
    return [r.label,basis,r.ytdP==null?'-':cell(r.ytdP,r),cell(r.ytdC,r),r.ytdP==null||r.ytdC==null?'-':((r.ytdC-r.ytdP>=0?'+':'')+nf((r.ytdC-r.ytdP)/r.div,r.dec)),pctTxt(r.ytdP==null?null:pct(r.ytdC,r.ytdP))]})};
  const by=l=>R.find(r=>r.label.startsWith(l));
  const cmp=(r,fmt)=>r.ytdP==null?'':` (1~${r.lastBoth}월 기준 전년 동기 ${fmt(r.ytdP)} → ${fmt(r.ytdC)}, ${pctTxt(pct(r.ytdC,r.ytdP))})`;
  const nm=v=>nf(v)+'명';
  const sa=by('매출'),nw=by('신규'),cm=by('누적'),ma=by('MAU'),vw=by('조회수'),pu=by('포인트 사용'),pe=by('포인트 적립');
  const L=[`1) ${Y}년 누계 실적 (1~${Mo}월)`,
    `① 매출 : ${eok(sa.all)}${cmp(sa,eok)}`,
    `② 회원 : 신규 가입 ${nm(nw.all)}${cmp(nw,nm)}, 누적 ${nm(cm.all)}${cm.ytdP!=null?` (전년 동월 대비 ${pctTxt(pct(cm.ytdC,cm.ytdP))})`:''}`,
    `③ 활동 : 월평균 MAU ${nm(ma.all)}, 조회수 ${nf((vw.all||0)/1e4)}만회${ma.ytdP==null?' (활동 지표는 2026년부터 집계되어 전년 비교 없음)':cmp(ma,nm)}`,
    `④ 포인트 : 사용 ${eok(pu.all)}${cmp(pu,eok)}, 적립 ${eok(pe.all)}${cmp(pe,eok)}`,
    `2) 월별 실적 및 전년 동기 비교 : 아래 표 참조`,
    `※ 출처 : Dashboard_DV (매출 ${M.meta?.salesBasis||''}${M.meta?.salesNote?', '+M.meta.salesNote:''}) · 동기화 ${M.syncedAt?fmtDT(M.syncedAt):'-'}`,
    `※ 표의 누계 : 매출·신규 회원·조회수·포인트는 합계, MAU는 월평균, 누적 회원은 최종월 값`,
    `※ 미집계 달은 ‘-’${partial?`, ${Mo}월은 집계 중인 부분 수치`:''}이며, 전년 동기 비교는 양년 모두 마감된 달만 합산함`];
  const yo=r=>r.ytdP!=null?`(전년 동기 대비 ${pctTxt(pct(r.ytdC,r.ytdP))})`:'';
  const sum=`${Y}년 1~${Mo}월 누계 매출 ${eok(sa.all)}${yo(sa)}, 신규 회원 ${nm(nw.all)}${yo(nw)}, 포인트 사용 ${eok(pu.all)}${yo(pu)}이며, 전년 비교는 양년 모두 마감된 1~${sa.lastBoth}월 기준임`;
  return {body:L.join('\n'),tables:[t1,t2],sum,raw:R.map(r=>({label:r.label,months,cur:r.cur,prev:r.prev,ytdCur:r.ytdC,ytdPrev:r.ytdP,comparableMonths:r.n}))};
}

// 규칙 기반 초안 (AI 미사용 시)
function draftReport(title,s,e,member){
  const F=collectFacts(s,e,member);
  const works=F.goals.flatMap(g=>g.works.map(w=>({...w,goal:g.title})));
  const by=k=>works.filter(w=>w.status===ST[k]);
  const recN=works.reduce((n,w)=>n+w.records.length,0);
  const cmN=works.reduce((n,w)=>n+w.records.reduce((k,r)=>k+r.comments.length,0)+w.meetingComments.length,0);
  const pLabel=`${ymdDot(s)} ~ ${ymdDot(e)}`;
  const last=(w,k)=>{for(let i=w.records.length-1;i>=0;i--){const v=firstLines(w.records[i][k],99).pop();if(v)return v}return ''};
  const summary=[];
  summary.push(works.length?`보고 기간(${pLabel}) TF 주요 업무 ${F.goals.filter(g=>g.id).length}건, 진행 업무 ${works.length}건(완료 ${by('done').length}, 진행중 ${by('progress').length}, 보류 ${by('hold').length}, 실패 ${by('fail').length})을 관리했으며 업무 기록은 ${recN}건임`:`보고 기간(${pLabel})에 기록된 TF 업무는 없음`);
  {const cs=CATS.map(c=>[c,F.goals.filter(g=>g.cat===c)]).filter(x=>x[1].length);
    if(cs.length)summary.push(`분류별 주요 업무는 ${cs.map(([c,gs])=>`${c} ${gs.length}건(진행 업무 ${gs.reduce((n,g)=>n+g.works.length,0)}건)`).join(', ')}임`);}
  if(F.meetings.length){const dec=F.meetings.flatMap(m=>firstLines(m.decisions,2)).slice(0,2);
    summary.push(`회의 ${F.meetings.length}회 진행(${F.meetings.slice(0,3).map(m=>m.title).join(', ')}${F.meetings.length>3?' 등':''})${dec.length?'. 주요 결정은 '+dec.join(', ')+'임':'함'}`);}
  else summary.push('보고 기간에 기록된 회의는 없음');
  if(F.nextPlans.length) summary.push(`차기 완료 예정 업무는 ${F.nextPlans.slice(0,3).map(t=>t.title).join(', ')}${F.nextPlans.length>3?` 외 ${F.nextPlans.length-3}건`:''}이며 ${ymdDot(F.nextEnd)}까지 진행 예정임`);
  if(F.overdue.length) summary.push(`완료일 경과 진행 업무 ${F.overdue.length}건(${F.overdue.slice(0,2).map(t=>t.title).join(', ')}${F.overdue.length>2?' 등':''})은 일정 재조정이 필요함`);
  if(cmN) summary.push(`업무·회의 코멘트 ${cmN}건이 기록되었으며 주요 이슈는 4장에 정리함`);

  const MT=buildMetrics(S.metrics,e);
  if(MT.sum)summary.unshift(MT.sum);
  const sec=[];
  sec.push({title:'1. 보고 개요',body:[`① 보고 기간 : ${pLabel} (${F.period.days}일)`,`② 대상 : ${member==='all'?'TF 전원':nameOf(member)} (기록 인원 ${F.members}명)`,`③ 업무 집계 기준 : 업무 기록일·진행 업무 완료일, 회의 일자 기준`,`④ 실적 집계 기준 : ${e.slice(0,4)}년 1월 ~ ${+e.slice(5,7)}월 (Dashboard_DV 월별 집계)`].join('\n')});
  sec.push({title:'2. 실적',body:MT.body,tables:MT.tables});
  {const L=[];let i=0;F.goals.forEach(g=>{const ds=g.works.filter(w=>w.status===ST.done);if(!ds.length)return;
      L.push(`${++i}) ${g.cat?'['+g.cat+'] ':''}${g.title}${g.status===ST.done?' (목표 달성)':''}`);
      ds.forEach((w,j)=>{L.push(`${circ(j)} ${w.title} (완료${w.due?' '+md(w.due):''}, ${w.owner})`);const d=last(w,'done');if(d)L.push(`- 한 일 : ${clip(d,90)}`)})});
    sec.push({title:'3. 주요 성과',body:L.length?L.join('\n'):'보고 기간에 완료된 진행 업무 없음'});}
  {const L=[];let k=0;
    F.goals.forEach(g=>{const os=g.works.filter(w=>w.status!==ST.done);if(!os.length)return;
      L.push(`${++k}) ${g.cat?'['+g.cat+'] ':''}${g.title}${g.due?` (완료일 ${md(g.due)})`:''}`);
      os.forEach((w,j)=>{L.push(`${circ(j)} ${w.title} : ${w.status}, ${w.owner}${w.due?`, 완료일 ${md(w.due)}`:''}${w.overdue?' (경과)':''}`);
        const d=last(w,'done');if(d)L.push(`- ${w.status===ST.hold||w.status===ST.fail?'사유·경과':'한 일'} : ${clip(d,90)}`);
        const t=last(w,'todo');if(t&&w.status!==ST.fail)L.push(`- 할 일 : ${clip(t,90)}`)})});
    const shown=new Set(works.map(w=>w.title+'|'+w.goal));
    const lateOut=F.overdue.filter(t=>!shown.has(t.title+'|'+t.goal));
    if(lateOut.length){L.push(`${++k}) 이전 기간 미완료 업무 (${lateOut.length}건)`);lateOut.forEach((t,j)=>L.push(`${circ(j)} ${t.title} : ${t.owner}, 완료일 ${md(t.due)} (${t.status})`))}
    const iss=[];works.forEach(w=>{w.records.forEach(r=>r.comments.forEach(c=>iss.push({w:w.title,c})));w.meetingComments.forEach(c=>iss.push({w:w.title,c,mt:c.meeting}))});
    if(iss.length){L.push(`${++k}) 코멘트 이슈`);iss.slice(-10).forEach((x,j)=>L.push(`${circ(j)} ${x.w} : ${clip(x.c.text,90)} (${x.c.by}${x.mt?', '+x.mt:''})`))}
    if(F.meetings.length){L.push(`${++k}) 회의 결정사항`);F.meetings.forEach((m,j)=>{L.push(`${circ(j)} ${m.title} (${md(m.date)}${m.attendees?', 참석 : '+clip(m.attendees,40):''})`);
      const d=firstLines(m.decisions,6),a=firstLines(m.actions,6);
      if(!d.length&&!a.length&&!m.workComments.length)firstLines(m.content,2).forEach(x=>L.push(`- ${clip(x,100)}`));
      d.forEach(x=>L.push(`- ${clip(x,120)}`));a.forEach(x=>L.push(`- 후속 조치 : ${clip(x,120)}`));
      m.workComments.slice(0,6).forEach(c=>L.push(`- [${c.work}] ${clip(c.text,100)} (${c.by})`))})}
    {const P=[];const seen=new Set();
      F.goals.forEach(g=>g.works.filter(w=>w.status===ST.progress||w.status===ST.hold).forEach(w=>{const t=last(w,'todo');if(!t)return;seen.add(w.title+'|'+g.title);P.push(`${w.title}${w.due?` (~${md(w.due)})`:''} : ${clip(t,90)}`)}));
      F.nextPlans.filter(t=>!seen.has(t.title+'|'+t.goal)).forEach(t=>P.push(`${t.title} (${md(t.due)} 완료 예정, ${t.owner})${t.todo?' : '+clip(firstLines(t.todo,99).pop()||'',80):''}`));
      if(P.length){L.push(`${++k}) 향후 계획`);P.forEach((x,j)=>L.push(`${circ(j)} ${x}`))}}
    sec.push({title:'4. 진행 사항',body:L.length?L.join('\n'):'특이 진행 사항 없음'});}

  const appendix=[];
  if(works.length)appendix.push({title:'업무 목록',head:['분류','주요 업무ID','주요 업무(목표)','진행 업무ID','진행 업무','담당','완료일','진행사항'],
    rows:F.goals.flatMap(g=>g.works.map(w=>[g.cat||'-',g.id||'-',g.title,w.id||'-',w.title,w.owner,w.due?ymdDot(w.due):'',w.status+(w.overdue?'(경과)':'')]))});
  if(recN)appendix.push({title:'업무 기록',head:['기록일','진행 업무','작성','한 일','할 일'],
    rows:works.flatMap(w=>w.records.map(r=>[ymdDot(r.date),w.title,r.owner,clip(r.done,70),clip(r.todo,70)])).sort((a,b)=>a[0].localeCompare(b[0]))});
  if(F.meetings.length)appendix.push({title:'회의 목록',head:['일자','회의명','참석자','결정사항'],rows:F.meetings.map(m=>[ymdDot(m.date),m.title,clip(m.attendees,40),clip(firstLines(m.decisions,3).join(' / '),120)])});
  return {v:3,title,period:{s,e},member,dateLine:`보고일 : ${korDate(new Date())}`,metaLine:`보고기간 : ${pLabel} · 대상 : ${member==='all'?'TF 전원':nameOf(member)}`,summary,sections:sec,appendix};
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
const tblHtml=t=>`<p class="rd-th">${esc(t.title)}</p><div class="tblwrap"><table class="rd-tbl ${t.head.length>8?'wide':''}"><thead><tr>${t.head.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${t.rows.map(row=>`<tr>${row.map((c,ci)=>`<td class="${ci>1&&t.head.length>4?'num':''}">${esc(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
function docHtml(r){
  return `<article class="rdoc">
    <h2 class="rd-title">${esc(r.title)}</h2>
    <p class="rd-meta">${esc(r.dateLine||'')}</p><p class="rd-meta">${esc(r.metaLine||'')}</p>
    ${(r.summary||[]).filter(x=>String(x).trim()).length?`<div class="rd-box"><p class="rd-boxh">■ 보고요약</p>${r.summary.filter(x=>String(x).trim()).map((x,i)=>`<p class="rd-sum">${i+1}. ${esc(x)}</p>`).join('')}</div>`:''}
    ${(r.sections||[]).map(s=>`<h3 class="rd-h">${esc(s.title)}</h3>${bodyHtml(s.body)}${(s.tables||[]).map(tblHtml).join('')}`).join('')}
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
      ${ta('re_sb_'+i,s.body,Math.min(18,Math.max(4,String(s.body).split('\n').length+1)))}
      ${(s.tables||[]).map((t,ti)=>`<div class="re-stbl"><div class="re-sech"><input class="input re-st" id="re_s${i}_tt_${ti}" value="${esc(t.title)}" aria-label="표 제목"><button class="btn sm danger" data-stdel="${i}:${ti}">표 삭제</button></div>
        <div class="tblwrap"><table class="rd-tbl re-tbl"><thead><tr>${t.head.map((h,ci)=>`<th><input class="re-cell" id="re_s${i}_h_${ti}_${ci}" value="${esc(h)}"></th>`).join('')}</tr></thead>
        <tbody>${t.rows.map((row,ri)=>`<tr>${row.map((c,ci)=>`<td><input class="re-cell" id="re_s${i}_c_${ti}_${ri}_${ci}" value="${esc(c)}"></td>`).join('')}</tr>`).join('')}</tbody></table></div></div>`).join('')}</section>`).join('')}
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
  d.sections.forEach((s,i)=>{s.title=$('#re_st_'+i).value;s.body=$('#re_sb_'+i).value;
    (s.tables||[]).forEach((t,ti)=>{t.title=$(`#re_s${i}_tt_${ti}`).value;t.head=t.head.map((h,ci)=>$(`#re_s${i}_h_${ti}_${ci}`).value);t.rows=t.rows.map((row,ri)=>row.map((c,ci)=>$(`#re_s${i}_c_${ti}_${ri}_${ci}`).value))})});
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
  document.querySelectorAll('[data-stdel]').forEach(b=>b.onclick=re(()=>{const[si,ti]=b.dataset.stdel.split(':').map(Number);d.sections[si].tables.splice(ti,1)}));
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
    <p class="muted" style="margin:0;font-size:13px">보고 개요 · 실적(Dashboard_DV 매출·회원·활동·포인트, 연초~보고월과 전년 동기 비교) · 주요 성과 · 진행 사항으로 초안을 만듭니다. 실적은 보고 기간 종료월 기준입니다. 초안은 화면에서 수정한 뒤 저장합니다.</p>
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
  $('#fNR').onsubmit=async ev=>{ev.preventDefault();const s=$('#nr_s').value,e=$('#nr_e').value;if(s>e){$('#nr_err').textContent='시작일이 종료일보다 늦습니다.';return}
    await loadMetrics();
    S.rEdit={id:newRptId(),...draftReport($('#nr_title').value.trim(),s,e,$('#nr_m').value)};S.rPrev=true;S.rEditBase=null;closeModal();render();
    toast('초안을 만들었습니다. 내용을 확인·수정한 뒤 저장하세요.')};
}
async function aiSummarize(){
  const d=S.rEdit,F=collectFacts(d.period.s,d.period.e,d.member||'all');await loadMetrics();{const MT=buildMetrics(S.metrics,d.period.e);F.performance=MT.raw||null;F.performanceText=MT.body}
  const keepT=(d.sections||[]).find(x=>/실적/.test(x.title))?.tables||[];
  const btn=$('#reAI');btn.disabled=true;btn.textContent='Claude AI 요약 중…';
  try{
    const {data,error}=await sb.functions.invoke('ai-report',{body:{action:'summarize',facts:F}});
    if(error){let code='';try{code=(await error.context.json()).error}catch{}throw new Error({ai_not_configured:'API 키가 등록되지 않았습니다.',too_large:'자료가 너무 많습니다. 기간을 줄여 주세요.',admin_only:'관리자만 사용할 수 있습니다.'}[code]||'AI 요약에 실패했습니다'+(code?` (${code})`:''))}
    d.summary=data.result.summary.map(String);d.sections=data.result.sections.map(s=>{const o={title:String(s.title||''),body:String(s.body||'')};if(/실적/.test(o.title)&&keepT.length)o.tables=keepT;return o});
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
  const tbl=t=>{const sz=t.head.length>10?14:t.head.length>7?16:18,numc=t.head.length>4;
    const cell=(txt,head,ci)=>new TableCell({borders,shading:head?{type:ShadingType.CLEAR,color:'auto',fill:G}:undefined,margins:{top:30,bottom:30,left:50,right:50},
      children:[new Paragraph({alignment:head?AlignmentType.CENTER:(numc&&ci>1?AlignmentType.RIGHT:undefined),children:[run(String(txt??''),{size:sz,bold:head})]})]});
    return new Table({width:{size:100,type:WidthType.PERCENTAGE},rows:[new TableRow({tableHeader:true,children:t.head.map((h,ci)=>cell(h,true,ci))}),...t.rows.map(row=>new TableRow({children:row.map((c,ci)=>cell(c,false,ci))}))]})};
  (r.sections||[]).forEach(s=>{kids.push(para(s.title,{bold:true,before:280,after:100}));kids.push(...bodyParas(s.body));
    (s.tables||[]).forEach(t=>{kids.push(para(t.title,{bold:true,before:160,after:80,size:20}));kids.push(tbl(t))})});
  if((r.appendix||[]).length){kids.push(para('■ 참고자료',{bold:true,before:320,after:120}));
    r.appendix.forEach((t,i)=>{kids.push(para(`${i+1}. ${t.title}`,{bold:true,before:160,after:80}));kids.push(tbl(t))});}
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
const goalOpts=sel=>{const gs=[...S.goals.values()].sort(byDueTitle);return `<option value="">주요 업무 선택</option>${gs.map(g=>`<option value="${esc(g.id)}" ${g.id===sel?'selected':''}>${g.cat?'['+esc(g.cat)+'] ':''}${esc(g.title)} · ${esc(g.id)}${g.status!=='progress'?` (${ST[g.status]})`:''}</option>`).join('')}<option value="__new">＋ 새 주요 업무 등록</option>`};
const workOpts=(gid,sel)=>{const ws=gid&&gid!=='__new'?worksOf(gid):[];return `<option value="">진행 업무 선택</option>${ws.map(w=>`<option value="${esc(w.id)}" ${w.id===sel?'selected':''}>${esc(w.title)} · ${esc(w.id)}${w.status!=='progress'?` (${ST[w.status]})`:''}</option>`).join('')}<option value="__new">＋ 새 진행 업무 등록</option>`};
// 업무 기록: 주요 업무 → 진행 업무를 불러와 선택(없으면 새로 등록) 후 한 일 / 할 일 기록
function modalRec(r,date,preset={}){
  const isNew=!r,ed=isNew||canEditRec(r);
  const w0=r?.workId?S.works.get(r.workId):null;
  let wid=preset.workId||w0?.id||'',gid=preset.goalId||(wid?S.works.get(wid)?.goalId:'')||'';
  openModal(`<form id="fRec"><div class="mh"><h2>${isNew?'업무 기록':ed?'업무 기록 수정':'업무 기록 보기'}</h2>${r?`<span class="jid">${esc(r.id)}</span>`:''}</div><div class="mb">
    ${r?.legacy?`<div class="banner">이전 방식으로 저장된 기록입니다 (업무명: ${esc(r.title)}). 주요 업무와 진행 업무를 지정해 저장하면 새 방식으로 바뀝니다.</div>`:''}
    <div class="field"><label for="rc_goal">주요 업무 <span class="muted" style="font-weight:400">= 달성할 목표</span></label><select class="input" id="rc_goal" ${ed?'':'disabled'}>${goalOpts(gid)}</select><div class="hint" id="rc_ginfo"></div></div>
    <div class="sub" id="rc_gnew" hidden><div class="g2"><div class="field"><label for="rc_gt">새 주요 업무명 (목표)</label><input class="input" id="rc_gt" maxlength="120" placeholder="예: 의사 채용 제휴 협력사 3곳 확보"></div><div class="field"><label for="rc_gd">주요 업무 완료일</label><input class="input" id="rc_gd" type="date"></div></div>
      <div class="field" style="margin-top:10px"><label>분류</label>${catSel('rc_gc','')}</div></div>
    <div class="field"><label for="rc_work">진행 업무</label><select class="input" id="rc_work" ${ed?'':'disabled'}>${workOpts(gid,wid)}</select><div class="hint" id="rc_winfo"></div></div>
    <div class="g2 sub" id="rc_wnew" hidden><div class="field"><label for="rc_wt">새 진행 업무명</label><input class="input" id="rc_wt" maxlength="120" placeholder="예: 제휴 제안서 발송" value="${r?.legacy?esc(r.title):''}"></div><div class="field"><label for="rc_wd">진행 업무 완료일</label><input class="input" id="rc_wd" type="date" value="${r?.legacy?esc(r.date):''}"></div></div>
    <div class="g2"><div class="field"><label for="rc_date">기록일</label><input class="input" id="rc_date" type="date" required value="${esc(r?.date||date||todayStr())}" ${ed?'':'readonly'}></div>
      <div class="field"><label>진행 업무 진행사항</label>${segSt('progress',ed)}</div></div>
    <div class="field"><label for="rc_done">한 일</label><textarea class="input" id="rc_done" rows="4" maxlength="5000" placeholder="이 날 진행한 일 (예: 협력사 A 유선 협의 — 단가 재견적 요청)" ${ed?'':'readonly'}>${esc(r?.done||'')}</textarea></div>
    <div class="field"><label for="rc_todo">할 일</label><textarea class="input" id="rc_todo" rows="3" maxlength="5000" placeholder="이어서 할 일 (예: 10/20까지 재견적 회신 확인)" ${ed?'':'readonly'}>${esc(r?.todo||'')}</textarea></div>
    ${r?`<p class="muted" style="margin:0;font-size:12px">작성 ${esc(nameOf(r.owner))} · <span class="mono">${fmtDT(r.createdAt)}</span></p>`:''}
    <div class="err" id="rc_err"></div></div>
    <div class="mf">${r&&ed?'<button type="button" class="btn danger" id="rcDel">삭제</button>':''}<span class="sp"></span><button type="button" class="btn" data-close>${ed?'취소':'닫기'}</button>${ed?`<button type="submit" class="btn primary" id="rcSave">${isNew?'기록':'저장'}</button>`:''}</div></form>`,true);
  const seg=bindSeg(S.works.get(wid)?.status||(r?.legacy?r.status:'progress'));const gcat=bindCat('rc_gc','');
  const sync=()=>{const g=$('#rc_goal').value,wv=$('#rc_work').value,go=S.goals.get(g),wo=S.works.get(wv);
    $('#rc_gnew').hidden=g!=='__new';$('#rc_wnew').hidden=wv!=='__new';
    $('#rc_ginfo').textContent=go?`${go.cat?'['+go.cat+'] ':''}${ST[go.status]}${go.due?' · 완료일 '+go.due:''} · 등록 ${nameOf(go.owner)} · 진행 업무 ${worksOf(go.id).length}건`:'';
    $('#rc_winfo').textContent=wo?`완료일 ${wo.due||'미정'} · 담당 ${nameOf(wo.owner)} · 기록 ${recsOf(wo.id).length}건`:''};
  $('#rc_goal').onchange=()=>{const g=$('#rc_goal').value;$('#rc_work').innerHTML=workOpts(g,'');if(g==='__new')$('#rc_work').value='__new';seg.set('progress');sync()};
  $('#rc_work').onchange=()=>{seg.set(S.works.get($('#rc_work').value)?.status||'progress');sync()};
  sync();
  if($('#rcDel'))$('#rcDel').onclick=()=>confirmBox(`${r.id} 업무 기록을 삭제할까요?`,`이 기록과 달린 코멘트 ${cCount('task',r.id)}개가 함께 삭제됩니다.`,()=>delRow('tasks',r.id,'업무 기록을 삭제했습니다'));
  $('#fRec').onsubmit=async ev=>{ev.preventDefault();if(!ed)return;const err=$('#rc_err');err.textContent='';
    let g=$('#rc_goal').value,wv=$('#rc_work').value;const d=$('#rc_date').value,done=$('#rc_done').value.trim(),todo=$('#rc_todo').value.trim(),status=seg.get();
    if(!g)return err.textContent='주요 업무를 선택하거나 새로 등록하세요.';
    if(g==='__new'&&!$('#rc_gt').value.trim())return err.textContent='새 주요 업무명(목표)을 입력하세요.';
    if(g==='__new'&&!gcat.get())return err.textContent='주요 업무 분류(매출·회원·콘텐츠·서비스)를 선택하세요.';
    if(!wv)return err.textContent='진행 업무를 선택하거나 새로 등록하세요.';
    if(wv==='__new'&&!$('#rc_wt').value.trim())return err.textContent='새 진행 업무명을 입력하세요.';
    if(!done&&!todo)return err.textContent='한 일 또는 할 일을 입력하세요.';
    const btn=$('#rcSave');btn.disabled=true;
    try{
      if(g==='__new'){const id=newId('GOL');const x=await safe(async()=>sb.from('tf_goals').insert({id,owner:S.me.id,enc:await encJ({title:$('#rc_gt').value.trim(),due:$('#rc_gd').value,status:'progress',cat:gcat.get()})}).select().single());await upsertLocal('tf_goals',x.data);g=id}
      if(wv==='__new'){const id=newId('WRK');const x=await safe(async()=>sb.from('tf_works').insert({id,goal_id:g,owner:S.me.id,enc:await encJ({title:$('#rc_wt').value.trim(),due:$('#rc_wd').value,status})}).select().single());await upsertLocal('tf_works',x.data);wv=id}
      else{const wo=S.works.get(wv);if(wo&&wo.status!==status){const x=await safe(async()=>sb.from('tf_works').update({enc:await encJ({...namePayload(wo),status})}).eq('id',wv).select().single());await upsertLocal('tf_works',x.data)}}
      const enc=await encJ({date:d,done,todo});
      const x=isNew?await safe(()=>sb.from('tasks').insert({id:newId('JOB',d),owner:S.me.id,work_id:wv,enc}).select().single(),'업무를 기록했습니다')
                   :await safe(()=>sb.from('tasks').update({work_id:wv,enc}).eq('id',r.id).select().single(),'저장했습니다');
      closeModal();
      if(S.view==='sched'){S.sel=d;const t=pYmd(d);S.month=new Date(t.getFullYear(),t.getMonth(),1)}
      await upsertLocal('tasks',x.data);
    }catch{btn.disabled=false}
  };
}
// 주요 업무 (= 목표) 등록·수정
function modalGoal(g){
  const isNew=!g,ws=g?worksOf(g.id):[];
  openModal(`<form id="fGoal"><div class="mh"><h2>${isNew?'주요 업무 등록':'주요 업무'}</h2>${g?`<span class="jid">${esc(g.id)}</span>`:''}</div><div class="mb">
    <p class="muted" style="margin:0;font-size:12.5px">주요 업무명은 달성해야 하는 목표로 적습니다. 등록하면 ID가 부여되고, 업무 기록 때 목록에서 불러와 같은 이름으로 쓰입니다.</p>
    <div class="field"><label for="gl_t">주요 업무명 (목표)</label><input class="input" id="gl_t" required maxlength="120" value="${esc(g?.title||'')}" placeholder="예: 의사 채용 제휴 협력사 3곳 확보"></div>
    <div class="field"><label>분류</label>${catSel('gl_c',g?.cat||'')}</div>
    <div class="g2"><div class="field"><label for="gl_d">완료일</label><input class="input" id="gl_d" type="date" value="${esc(g?.due||'')}"></div><div class="field"><label>진행사항</label>${segSt(g?.status||'progress')}</div></div>
    ${g?`<div class="field"><label>진행 업무 ${ws.length}건</label><div class="wlist" style="margin-left:0">${ws.map(w=>`<div class="wnode"><button type="button" class="wbtn" data-work="${esc(w.id)}"><span class="jid">${esc(w.id)}</span><span class="wt">${esc(w.title)}</span></button>${stBadge(w)}${w.due?`<span class="mono muted">~${md(w.due)}</span>`:''}</div>`).join('')||'<span class="muted" style="font-size:13px">없음</span>'}</div>
      <div><button type="button" class="btn sm" data-addwork="${esc(g.id)}">+ 진행 업무 추가</button></div></div>
      <p class="muted" style="margin:0;font-size:12px">등록 ${esc(nameOf(g.owner))} · <span class="mono">${fmtDT(g.createdAt)}</span>${g.updatedAt-g.createdAt>1000?` · 수정 <span class="mono">${fmtDT(g.updatedAt)}</span>`:''}</p>`:''}
  </div><div class="mf">${g&&isAdmin()?'<button type="button" class="btn danger" id="glDel">삭제</button>':''}<span class="sp"></span><button type="button" class="btn" data-close>취소</button><button type="submit" class="btn primary" id="glSave">${isNew?'등록':'저장'}</button></div></form>`);
  const seg=bindSeg(g?.status||'progress'),gc=bindCat('gl_c',g?.cat||'');
  bindWorkLinks();
  if($('#glDel'))$('#glDel').onclick=()=>confirmGoalDel(g);
  $('#fGoal').onsubmit=async ev=>{ev.preventDefault();if(!gc.get())return toast('분류(매출·회원·콘텐츠·서비스)를 선택하세요.');$('#glSave').disabled=true;
    const pl={title:$('#gl_t').value.trim(),due:$('#gl_d').value,status:seg.get(),cat:gc.get()};
    try{const enc=await encJ(pl);
      const x=isNew?await safe(()=>sb.from('tf_goals').insert({id:newId('GOL'),owner:S.me.id,enc}).select().single(),'주요 업무를 등록했습니다')
                   :await safe(()=>sb.from('tf_goals').update({enc}).eq('id',g.id).select().single(),'저장했습니다. 이 업무명은 모든 기록·Report에 같이 반영됩니다.');
      closeModal();await upsertLocal('tf_goals',x.data);
      if(isNew)modalWork(null,x.data.id);
    }catch{$('#glSave')&&($('#glSave').disabled=false)}};
}
// 진행 업무 등록·수정
function modalWork(w,goalId){
  const isNew=!w,rs=w?recsOf(w.id):[];
  const gid=w?.goalId||goalId||'';
  openModal(`<form id="fWork"><div class="mh"><h2>${isNew?'진행 업무 등록':'진행 업무'}</h2>${w?`<span class="jid">${esc(w.id)}</span>`:''}</div><div class="mb">
    ${w?'<p class="muted" style="margin:0;font-size:12.5px">기록 내용(한 일·할 일)을 고치거나 덧붙이려면 아래 업무 기록의 ‘수정’을 누르세요.</p>':''}
    <div class="field"><label for="wk_g">주요 업무</label><select class="input" id="wk_g" required>${goalOpts(gid).replace('<option value="__new">＋ 새 주요 업무 등록</option>','')}</select></div>
    <div class="field"><label for="wk_t">진행 업무명</label><input class="input" id="wk_t" required maxlength="120" value="${esc(w?.title||'')}" placeholder="예: 제휴 제안서 발송"></div>
    <div class="g2"><div class="field"><label for="wk_d">완료일</label><input class="input" id="wk_d" type="date" value="${esc(w?.due||'')}"></div><div class="field"><label>진행사항</label>${segSt(w?.status||'progress')}</div></div>
    ${w?`<div class="field"><label>업무 기록 ${rs.length}건</label><div class="wrecs">${rs.slice().reverse().map(r=>`<div class="rrec"><div class="meta" style="margin:0"><span class="mono">${fmtMD(r.date)}</span><span>${esc(nameOf(r.owner))}</span><span class="jid">${esc(r.id)}</span><button type="button" class="lnk" data-rec="${esc(r.id)}">${canEditRec(r)?'수정':'보기'}</button></div>${rLines(r)}</div>`).join('')||'<span class="muted" style="font-size:13px">아직 기록이 없습니다.</span>'}</div></div>
      <p class="muted" style="margin:0;font-size:12px">담당(등록) ${esc(nameOf(w.owner))} · <span class="mono">${fmtDT(w.createdAt)}</span></p>`:''}
  </div><div class="mf">${w&&isAdmin()?'<button type="button" class="btn danger" id="wkDel">삭제</button>':''}${w?`<button type="button" class="btn" id="wkRec">+ 이 업무에 기록</button>`:''}<span class="sp"></span><button type="button" class="btn" data-close>취소</button><button type="submit" class="btn primary" id="wkSave">${isNew?'등록':'저장'}</button></div></form>`,!!w);
  const seg=bindSeg(w?.status||'progress');
  bindWorkLinks();
  if($('#wkDel'))$('#wkDel').onclick=()=>confirmWorkDel(w);
  if($('#wkRec'))$('#wkRec').onclick=()=>modalRec(null,todayStr(),{workId:w.id});
  $('#fWork').onsubmit=async ev=>{ev.preventDefault();const g=$('#wk_g').value;if(!g)return toast('주요 업무를 선택하세요.');$('#wkSave').disabled=true;
    try{const enc=await encJ({title:$('#wk_t').value.trim(),due:$('#wk_d').value,status:seg.get()});
      const x=isNew?await safe(()=>sb.from('tf_works').insert({id:newId('WRK'),goal_id:g,owner:S.me.id,enc}).select().single(),'진행 업무를 등록했습니다')
                   :await safe(()=>sb.from('tf_works').update({goal_id:g,enc}).eq('id',w.id).select().single(),'저장했습니다. 이 업무명은 모든 기록·Report에 같이 반영됩니다.');
      closeModal();await upsertLocal('tf_works',x.data);
    }catch{$('#wkSave')&&($('#wkSave').disabled=false)}};
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
