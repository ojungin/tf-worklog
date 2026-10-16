-- =====================================================================
-- 닥터빌 TF 워크로그 — 보고서 실적 데이터 (Dashboard_DV 월별 집계)
--  * GitHub Actions(sync-metrics.yml)가 매일 Dashboard_DV에서 월별 집계값만 읽어 저장
--  * 쓰기는 Management API(배포 토큰) 전용, 화면에서는 활성 사용자 조회만 가능
-- 여러 번 실행해도 안전합니다.
-- =====================================================================
create table if not exists public.tf_metrics (
  key         text primary key,                      -- 'dv'
  data        jsonb not null,                        -- {sales, members, activity, points, meta}
  updated_at  timestamptz not null default now()
);
alter table public.tf_metrics enable row level security;
revoke all on public.tf_metrics from anon;
grant select on public.tf_metrics to authenticated;
drop policy if exists tf_metrics_select on public.tf_metrics;
create policy tf_metrics_select on public.tf_metrics for select to authenticated using (public.tf_is_active_member());
