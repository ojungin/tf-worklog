-- =====================================================================
-- 닥터빌 TF 워크로그 — 주요 업무 / 진행 업무 / 회의-업무 코멘트 / 코멘트 사용자 로그
--  * tf_goals  : 주요 업무 (= 달성할 목표). ID GOL-YYYYMMDD-XXXX
--  * tf_works  : 진행 업무 (주요 업무 하위). ID WRK-YYYYMMDD-XXXX
--  * tasks     : 일자별 업무 기록(한 일 / 할 일). work_id 로 진행 업무에 연결 (기존 기록은 null)
--  * comments  : work_id 추가 → 회의록(meeting_id) + 진행 업무(work_id) 코멘트. 작성자 본인 수정 허용
--  * tf_comment_log : 코멘트 작성·수정·삭제 이력 (DB 트리거가 자동 기록, 관리자만 조회)
-- 모든 본문은 브라우저에서 암호화된 암호문(enc)으로만 저장됩니다. 여러 번 실행해도 안전합니다.
-- =====================================================================

create table if not exists public.tf_goals (
  id          text primary key check (id ~ '^GOL-[0-9]{8}-[A-Z0-9]{4,8}$'),
  owner       uuid references public.profiles(id) on delete set null,
  enc         jsonb not null,                       -- {title(목표), due, status}
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists public.tf_works (
  id          text primary key check (id ~ '^WRK-[0-9]{8}-[A-Z0-9]{4,8}$'),
  goal_id     text not null references public.tf_goals(id) on delete cascade,
  owner       uuid references public.profiles(id) on delete set null,
  enc         jsonb not null,                       -- {title, due, status}
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);
create index if not exists tf_works_goal_idx on public.tf_works(goal_id);

alter table public.tasks    add column if not exists work_id text references public.tf_works(id) on delete cascade;
create index if not exists tasks_work_idx on public.tasks(work_id);

alter table public.comments add column if not exists work_id text references public.tf_works(id) on delete cascade;
alter table public.comments add column if not exists updated_at timestamptz;
create index if not exists comments_work_idx on public.comments(work_id);
alter table public.comments drop constraint if exists tf_comments_work_meeting;
alter table public.comments add constraint tf_comments_work_meeting check (work_id is null or meeting_id is not null);

-- 등록자·생성시각 변경 방지
create or replace function public.tf_protect_owner_cols()
returns trigger language plpgsql as $$
begin
  new.owner := old.owner; new.created_at := old.created_at; new.updated_at := now();
  return new;
end $$;
drop trigger if exists tf_goals_protect on public.tf_goals;
create trigger tf_goals_protect before update on public.tf_goals for each row execute function public.tf_protect_owner_cols();
drop trigger if exists tf_works_protect on public.tf_works;
create trigger tf_works_protect before update on public.tf_works for each row execute function public.tf_protect_owner_cols();

-- 코멘트: 작성자·대상·작성시각 변경 방지 (본문만 수정 가능)
create or replace function public.tf_protect_comment_cols()
returns trigger language plpgsql as $$
begin
  new.author := old.author; new.created_at := old.created_at;
  new.task_id := old.task_id; new.meeting_id := old.meeting_id; new.work_id := old.work_id;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists tf_comments_protect on public.comments;
create trigger tf_comments_protect before update on public.comments for each row execute function public.tf_protect_comment_cols();

-- 코멘트 사용자 로그
create table if not exists public.tf_comment_log (
  id          bigint generated always as identity primary key,
  comment_id  uuid not null,
  action      text not null check (action in ('create','update','delete')),
  actor       uuid,                                 -- 작업한 사용자
  author      uuid,                                 -- 코멘트 작성자
  task_id     text,
  meeting_id  text,
  work_id     text,
  enc         jsonb,                                -- 작성·수정 후 내용 / 삭제 전 내용 (암호문)
  prev_enc    jsonb,                                -- 수정 전 내용 (암호문)
  created_at  timestamptz not null default now()
);
create index if not exists tf_comment_log_comment_idx on public.tf_comment_log(comment_id);

create or replace function public.tf_log_comment()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    insert into public.tf_comment_log(comment_id, action, actor, author, task_id, meeting_id, work_id, enc)
    values (new.id, 'create', auth.uid(), new.author, new.task_id, new.meeting_id, new.work_id, new.enc);
  elsif tg_op = 'UPDATE' then
    if new.enc is distinct from old.enc then
      insert into public.tf_comment_log(comment_id, action, actor, author, task_id, meeting_id, work_id, enc, prev_enc)
      values (new.id, 'update', auth.uid(), new.author, new.task_id, new.meeting_id, new.work_id, new.enc, old.enc);
    end if;
  else
    insert into public.tf_comment_log(comment_id, action, actor, author, task_id, meeting_id, work_id, enc)
    values (old.id, 'delete', auth.uid(), old.author, old.task_id, old.meeting_id, old.work_id, old.enc);
  end if;
  return null;
end $$;
revoke all on function public.tf_log_comment() from public;
drop trigger if exists tf_comments_log on public.comments;
create trigger tf_comments_log after insert or update or delete on public.comments for each row execute function public.tf_log_comment();

-- RLS
alter table public.tf_goals       enable row level security;
alter table public.tf_works       enable row level security;
alter table public.tf_comment_log enable row level security;
revoke all on public.tf_goals, public.tf_works, public.tf_comment_log from anon;
grant select, insert, update, delete on public.tf_goals, public.tf_works to authenticated;
grant select on public.tf_comment_log to authenticated;
grant update on public.comments to authenticated;

-- 주요·진행 업무: 전원 조회·등록·수정(팀 공용 업무명), 삭제는 관리자
drop policy if exists tf_goals_select on public.tf_goals;
drop policy if exists tf_goals_insert on public.tf_goals;
drop policy if exists tf_goals_update on public.tf_goals;
drop policy if exists tf_goals_delete on public.tf_goals;
create policy tf_goals_select on public.tf_goals for select to authenticated using (public.tf_is_active_member());
create policy tf_goals_insert on public.tf_goals for insert to authenticated with check (public.tf_is_active_member() and owner = auth.uid());
create policy tf_goals_update on public.tf_goals for update to authenticated using (public.tf_is_active_member()) with check (public.tf_is_active_member());
create policy tf_goals_delete on public.tf_goals for delete to authenticated using (public.tf_is_admin());

drop policy if exists tf_works_select on public.tf_works;
drop policy if exists tf_works_insert on public.tf_works;
drop policy if exists tf_works_update on public.tf_works;
drop policy if exists tf_works_delete on public.tf_works;
create policy tf_works_select on public.tf_works for select to authenticated using (public.tf_is_active_member());
create policy tf_works_insert on public.tf_works for insert to authenticated with check (public.tf_is_active_member() and owner = auth.uid());
create policy tf_works_update on public.tf_works for update to authenticated using (public.tf_is_active_member()) with check (public.tf_is_active_member());
create policy tf_works_delete on public.tf_works for delete to authenticated using (public.tf_is_admin());

-- 코멘트 수정: 작성자 본인만
drop policy if exists tf_comments_update on public.comments;
create policy tf_comments_update on public.comments for update to authenticated
  using (public.tf_is_active_member() and author = auth.uid()) with check (public.tf_is_active_member() and author = auth.uid());

-- 코멘트 로그: 관리자만 조회 (기록은 트리거 전용)
drop policy if exists tf_comment_log_select on public.tf_comment_log;
create policy tf_comment_log_select on public.tf_comment_log for select to authenticated using (public.tf_is_admin());

-- 실시간 반영
do $$
declare t text;
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    foreach t in array array['tf_goals','tf_works'] loop
      if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename=t) then
        execute format('alter publication supabase_realtime add table public.%I', t);
      end if;
    end loop;
  end if;
end $$;
