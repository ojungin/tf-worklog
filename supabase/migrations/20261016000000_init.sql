-- =====================================================================
-- 닥터빌 TF 워크로그 — Supabase 스키마
-- Supabase 대시보드 > SQL Editor 에 전체를 붙여 넣고 Run 하세요.
--
-- 저장 원칙
--  * 업무·회의록·코멘트 본문, 사용자 이름은 브라우저에서 AES-256-GCM 으로 암호화된
--    암호문(jsonb {iv, ct})으로만 저장됩니다. DB·Supabase 관리자도 내용을 읽을 수 없습니다.
--  * 평문으로 남는 것은 접근제어에 꼭 필요한 값뿐입니다:
--    아이디(username), 권한(role), 활성 여부, 작성자 UUID, 업무ID/회의록ID, 생성·수정 시각.
--  * 계정 생성·삭제·권한/상태 변경·비밀번호 초기화는 Edge Function(admin-users)만 수행합니다.
-- =====================================================================

create extension if not exists pgcrypto;

-- ---------- 테이블 ----------
create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  username    text not null unique check (username ~ '^[A-Za-z0-9._-]{3,30}$'),
  name_enc    jsonb not null,                         -- 암호화된 이름
  role        text not null default 'user' check (role in ('admin','user')),
  active      boolean not null default true,
  created_at  timestamptz not null default now()
);

-- 사용자별로 '워크스페이스 데이터키'를 본인 비밀번호 파생키로 감싼 값
create table if not exists public.key_wraps (
  user_id     uuid primary key references auth.users(id) on delete cascade,
  salt        text not null,
  iter        integer not null check (iter >= 100000),
  wk          jsonb not null,
  updated_at  timestamptz not null default now()
);

-- 워크스페이스 1행 (초기화 여부 + 키 검증용 암호문)
create table if not exists public.workspace (
  id          integer primary key default 1 check (id = 1),
  check_enc   jsonb not null,
  created_at  timestamptz not null default now()
);

create table if not exists public.tasks (
  id          text primary key check (id ~ '^JOB-[0-9]{8}-[A-Z0-9]{4,8}$'),   -- 업무ID
  owner       uuid references public.profiles(id) on delete set null,
  enc         jsonb not null,                         -- {title,date,status,detail,doneAt}
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists public.meetings (
  id          text primary key check (id ~ '^MTG-[0-9]{8}-[A-Z0-9]{4,8}$'),
  author      uuid references public.profiles(id) on delete set null,
  enc         jsonb not null,                         -- {title,date,time,place,attendees,agenda,...}
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists public.comments (
  id          uuid primary key default gen_random_uuid(),
  task_id     text references public.tasks(id) on delete cascade,
  meeting_id  text references public.meetings(id) on delete cascade,
  author      uuid references public.profiles(id) on delete set null,
  enc         jsonb not null,                         -- {text, authorName}
  created_at  timestamptz not null default now(),     -- 코멘트 작성 시각(서버 기준)
  constraint comments_one_target check ((task_id is null) <> (meeting_id is null))
);
create index if not exists comments_task_idx    on public.comments(task_id);
create index if not exists comments_meeting_idx on public.comments(meeting_id);

-- ---------- 권한 헬퍼 ----------
create or replace function public.is_active_member()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and active);
$$;

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and active and role = 'admin');
$$;

-- 로그인 전 화면에서 '초기 설정 필요' 여부만 확인 (내용은 노출하지 않음)
create or replace function public.workspace_initialized()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.workspace);
$$;

revoke all on function public.is_active_member()      from public;
revoke all on function public.is_admin()              from public;
revoke all on function public.workspace_initialized() from public;
grant execute on function public.is_active_member()      to authenticated;
grant execute on function public.is_admin()              to authenticated;
grant execute on function public.workspace_initialized() to anon, authenticated;

-- ---------- 작성자·생성시각 변경 방지 트리거 ----------
create or replace function public.protect_task_cols()
returns trigger language plpgsql as $$
begin
  new.owner := old.owner; new.created_at := old.created_at; new.updated_at := now();
  return new;
end $$;
create or replace function public.protect_meeting_cols()
returns trigger language plpgsql as $$
begin
  new.author := old.author; new.created_at := old.created_at; new.updated_at := now();
  return new;
end $$;
drop trigger if exists tasks_protect on public.tasks;
create trigger tasks_protect before update on public.tasks for each row execute function public.protect_task_cols();
drop trigger if exists meetings_protect on public.meetings;
create trigger meetings_protect before update on public.meetings for each row execute function public.protect_meeting_cols();

-- ---------- RLS ----------
alter table public.profiles  enable row level security;
alter table public.key_wraps enable row level security;
alter table public.workspace enable row level security;
alter table public.tasks     enable row level security;
alter table public.meetings  enable row level security;
alter table public.comments  enable row level security;

-- 비로그인(anon)은 어떤 테이블도 접근 불가
revoke all on public.profiles, public.key_wraps, public.workspace, public.tasks, public.meetings, public.comments from anon;
grant select on public.profiles, public.key_wraps, public.workspace to authenticated;
grant select, insert, update, delete on public.tasks, public.meetings to authenticated;
grant select, insert, delete on public.comments to authenticated;

-- profiles: 활성 사용자는 조회만. 쓰기는 Edge Function(service role) 전용
drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated using (public.is_active_member());

-- key_wraps: 본인 것만 조회. 쓰기는 Edge Function 전용
drop policy if exists key_wraps_select on public.key_wraps;
create policy key_wraps_select on public.key_wraps for select to authenticated using (user_id = auth.uid());

drop policy if exists workspace_select on public.workspace;
create policy workspace_select on public.workspace for select to authenticated using (public.is_active_member());

-- tasks: 전원 조회 / 본인 명의로 등록 / 수정·삭제는 본인 또는 관리자
drop policy if exists tasks_select on public.tasks;
drop policy if exists tasks_insert on public.tasks;
drop policy if exists tasks_update on public.tasks;
drop policy if exists tasks_delete on public.tasks;
create policy tasks_select on public.tasks for select to authenticated using (public.is_active_member());
create policy tasks_insert on public.tasks for insert to authenticated with check (public.is_active_member() and owner = auth.uid());
create policy tasks_update on public.tasks for update to authenticated
  using (public.is_active_member() and (owner = auth.uid() or public.is_admin()));
create policy tasks_delete on public.tasks for delete to authenticated
  using (public.is_active_member() and (owner = auth.uid() or public.is_admin()));

-- meetings: 전원 조회 / 본인 명의로 작성 / 수정은 작성자·관리자 / 삭제는 관리자
drop policy if exists meetings_select on public.meetings;
drop policy if exists meetings_insert on public.meetings;
drop policy if exists meetings_update on public.meetings;
drop policy if exists meetings_delete on public.meetings;
create policy meetings_select on public.meetings for select to authenticated using (public.is_active_member());
create policy meetings_insert on public.meetings for insert to authenticated with check (public.is_active_member() and author = auth.uid());
create policy meetings_update on public.meetings for update to authenticated
  using (public.is_active_member() and (author = auth.uid() or public.is_admin()));
create policy meetings_delete on public.meetings for delete to authenticated using (public.is_admin());

-- comments: 전원 조회 / 본인 명의로 작성 / 삭제는 작성자·관리자 (수정 없음)
drop policy if exists comments_select on public.comments;
drop policy if exists comments_insert on public.comments;
drop policy if exists comments_delete on public.comments;
create policy comments_select on public.comments for select to authenticated using (public.is_active_member());
create policy comments_insert on public.comments for insert to authenticated
  with check (public.is_active_member() and author = auth.uid() and created_at > now() - interval '1 minute');
create policy comments_delete on public.comments for delete to authenticated
  using (public.is_active_member() and (author = auth.uid() or public.is_admin()));

-- ---------- 실시간 반영 ----------
do $$
declare t text;
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    foreach t in array array['profiles','tasks','meetings','comments'] loop
      if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename=t) then
        execute format('alter publication supabase_realtime add table public.%I', t);
      end if;
    end loop;
  end if;
end $$;
