-- =====================================================================
-- 닥터빌 TF 워크로그 — 보고서 기능
--  * reports           : 보고서 본문(암호문). 관리자가 생성, 활성 사용자 전원 열람·수정·저장
--  * report_revisions  : 저장 이력(누가·언제 + 저장 시점 스냅샷 암호문). 보고서 본문에는 기록하지 않음
--    이력은 DB 트리거가 자동 기록하므로 화면에서 누락·위조할 수 없음
-- 여러 번 실행해도 안전합니다.
-- =====================================================================

create table if not exists public.reports (
  id          text primary key check (id ~ '^RPT-[0-9]{8}-[A-Z0-9]{4,8}$'),
  created_by  uuid references public.profiles(id) on delete set null,
  enc         jsonb not null,                       -- {title, period, summary, sections, appendix ...}
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

create table if not exists public.report_revisions (
  id          bigint generated always as identity primary key,
  report_id   text not null references public.reports(id) on delete cascade,
  editor      uuid references public.profiles(id) on delete set null,
  action      text not null check (action in ('create','update')),
  enc         jsonb not null,                       -- 저장 시점 보고서 스냅샷(암호문)
  created_at  timestamptz not null default now()
);
create index if not exists report_revisions_report_idx on public.report_revisions(report_id, created_at desc);

-- 작성자·생성시각 변경 방지
create or replace function public.protect_report_cols()
returns trigger language plpgsql as $$
begin
  new.created_by := old.created_by; new.created_at := old.created_at; new.updated_at := now();
  return new;
end $$;
drop trigger if exists reports_protect on public.reports;
create trigger reports_protect before update on public.reports for each row execute function public.protect_report_cols();

-- 저장 이력 자동 기록 (생성·내용 변경 시)
create or replace function public.log_report_revision()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    insert into public.report_revisions(report_id, editor, action, enc) values (new.id, auth.uid(), 'create', new.enc);
  elsif new.enc is distinct from old.enc then
    insert into public.report_revisions(report_id, editor, action, enc) values (new.id, auth.uid(), 'update', new.enc);
  end if;
  return null;
end $$;
revoke all on function public.log_report_revision() from public;
drop trigger if exists reports_log on public.reports;
create trigger reports_log after insert or update on public.reports for each row execute function public.log_report_revision();

-- RLS
alter table public.reports          enable row level security;
alter table public.report_revisions enable row level security;
revoke all on public.reports, public.report_revisions from anon;
grant select, insert, update, delete on public.reports to authenticated;
grant select on public.report_revisions to authenticated;

drop policy if exists reports_select on public.reports;
drop policy if exists reports_insert on public.reports;
drop policy if exists reports_update on public.reports;
drop policy if exists reports_delete on public.reports;
create policy reports_select on public.reports for select to authenticated using (public.is_active_member());
create policy reports_insert on public.reports for insert to authenticated with check (public.is_admin() and created_by = auth.uid());
create policy reports_update on public.reports for update to authenticated using (public.is_active_member()) with check (public.is_active_member());
create policy reports_delete on public.reports for delete to authenticated using (public.is_admin());

drop policy if exists report_revisions_select on public.report_revisions;
create policy report_revisions_select on public.report_revisions for select to authenticated using (public.is_active_member());

-- 실시간 반영
do $$
declare t text;
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    foreach t in array array['reports','report_revisions'] loop
      if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename=t) then
        execute format('alter publication supabase_realtime add table public.%I', t);
      end if;
    end loop;
  end if;
end $$;
