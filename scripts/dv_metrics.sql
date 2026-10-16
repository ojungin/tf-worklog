-- Dashboard_DV(datasets) → TF 보고서용 월별 실적 집계 (읽기 전용 SELECT)
-- 결과: 한 행 {metrics: {...}}. 월 키는 'YYYY-MM'
with
sales as (
  select y.key as yr, i, sum(coalesce(nullif(r->'m'->>i,'')::numeric, 0)) as v
  from datasets d, jsonb_each(d.data->'sales'->'years') y,
       jsonb_array_elements(y.value->'rows') r, generate_series(0, 11) i
  where d.key = 'api|sales'
  group by 1, 2
),
sales_m as (
  select jsonb_object_agg(yr || '-' || lpad((i + 1)::text, 2, '0'), v) as m from sales
),
mem as (
  select jsonb_object_agg(x->>'month', jsonb_build_object('new', (x->>'new')::numeric, 'cum', (x->>'cumulative')::numeric)) as m
  from datasets d, jsonb_array_elements(d.data->'snap'->'monthlySeries') x
  where d.key = 'api|get|dv'
),
act as (
  select jsonb_object_agg(r->>0, jsonb_build_object('mau', (r->>4)::numeric, 'views', (r->>8)::numeric)) as m
  from datasets d, jsonb_array_elements(d.data->'activity'->'monthly'->'rows') r
  where d.key = 'api|activity' and r->>1 = '전체'
),
pts as (
  select jsonb_object_agg(mo.v, jsonb_build_object(
           'use',  nullif(d.data->'use'->'amt'->>(mo.n::int - 1), '')::numeric,
           'earn', nullif(d.data->'earn'->'amt'->>(mo.n::int - 1), '')::numeric)) as m
  from datasets d, jsonb_array_elements_text(d.data->'months') with ordinality as mo(v, n)
  where d.key = 'file|data/points.enc.json'
),
meta as (
  select jsonb_build_object(
    'salesAt',  (select fetched_at from datasets where key = 'api|sales'),
    'salesBasis', (select data->'sales'->>'basis' from datasets where key = 'api|sales'),
    'salesNote',  (select data->'sales'->>'note' from datasets where key = 'api|sales'),
    'memberAt', (select data->'snap'->'monthly'->>'asOf' from datasets where key = 'api|get|dv'),
    'actAt',    (select fetched_at from datasets where key = 'api|activity'),
    'ptsAt',    (select data->>'generatedAtKst' from datasets where key = 'file|data/points.enc.json'),
    'ptsLen',   (select jsonb_array_length(data->'months') || '/' || jsonb_array_length(data->'use'->'amt') || '/' || jsonb_array_length(data->'earn'->'amt') from datasets where key = 'file|data/points.enc.json')
  ) as m
)
select jsonb_build_object(
  'v', 1,
  'sales',   (select m from sales_m),
  'members', (select m from mem),
  'activity',(select m from act),
  'points',  (select m from pts),
  'meta',    (select m from meta)
) as metrics;
