// 닥터빌 TF 워크로그 — 보고서 AI 요약 Edge Function
// 배포: supabase functions deploy ai-report --no-verify-jwt  (호출자 검증은 코드에서 수행)
// Secret: TF_ANTHROPIC_API_KEY (없으면 비활성 상태로 응답), TF_CLAUDE_MODEL(선택), TF_ALLOWED_ORIGIN(선택)
// 전달받은 업무·회의록 요약 재료는 Claude API 호출에만 쓰고 어디에도 저장하지 않습니다.

import { createClient } from "jsr:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": Deno.env.get("TF_ALLOWED_ORIGIN") ?? "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

const API_KEY = Deno.env.get("TF_ANTHROPIC_API_KEY") ?? "";
const MODEL = Deno.env.get("TF_CLAUDE_MODEL") || "claude-sonnet-4-5";
const MAX_INPUT = 150_000; // 요약 재료 최대 크기(문자)

const SYSTEM = `당신은 의료 플랫폼 '닥터빌'(운영사 엠서클) TF의 업무 보고서를 작성하는 보고서 담당자입니다.
입력으로 보고 기간의 업무가 JSON으로 주어집니다. 구조: goals(주요 업무 = 달성할 목표, ID·완료일·진행사항) → works(진행 업무, ID·담당·완료일·진행사항[완료/진행중/보류/실패]) → records(일자별 업무 기록: done=한 일, todo=할 일, 기록별 코멘트) 및 meetingComments(회의에서 해당 진행 업무에 남긴 코멘트), 그리고 회의록(meetings)과 완료일 경과·차기 예정 업무.
주요 업무명과 진행 업무명은 입력에 있는 단어 그대로 사용해 보고서 전체에서 같은 이름으로 표기합니다.
performance(실적: 매출·신규/누적 회원·MAU·조회수·포인트 사용/적립의 연초~보고월 월별 값과 전년 동월, 누계)와 performanceText(규칙 기반 실적 문안)가 함께 주어집니다. '2. 실적'은 performance 수치만 사용해 누계와 전년 동기 대비 증감률 중심으로 작성하고(월별 표는 화면에서 자동으로 붙으므로 본문에 표를 쓰지 않음), 수치를 새로 계산하거나 추정하지 않습니다.
'3. 주요 성과'는 진행사항이 '완료'인 진행 업무만 대상으로, 분류(goals.cat: 매출·회원·콘텐츠·서비스, 없으면 미분류)별로 묶어 아래 형식으로 씁니다. 같은 분류의 주요 업무는 1. 2. 로 번호를 매깁니다.
  "[분류명]" / "1. 주요 업무명 (진행사항, 완료일 M.D)" / "1) 진행 업무명 (완료, 완료일 M.D)" / "한 일" / "(1) 완료한 내용과 결과 요약" / "(2) …" / 필요 시 "할 일" / "(1) …"
'4. 진행 사항'은 화면에서 입력 원문(한 일·할 일)으로 자동 수합되므로 body에 "(자동 수합)"만 적습니다. 보고요약에는 진행 중 업무의 핵심도 반영합니다.
경영진 보고용 '보고의 건' 양식에 맞춰 요약 정리합니다.

작성 원칙
- 한국어 개조식, 문장 끝은 '~함', '~임', '~예정'으로 끝냄. 과장·추측 금지, 입력에 없는 사실·수치는 만들지 않음
- 핵심 수치(건수, 기한, 담당)를 살리고 중복은 합침. 담당자 이름은 입력에 있는 그대로 사용
- 주요 업무(목표) 단위로 묶어 목표 대비 달성 여부를 중심으로 정리하고, 보고요약에는 완료일이 지난 미완료 업무, 보류·실패 업무, 코멘트로 제기된 주요 이슈, 회의 결정사항을 빠뜨리지 않음
- 구두 합의로 보이는 내용이 문서화되지 않았으면 '기록 필요'로 표시

본문 표기 규칙 (줄 단위)
- "[분류명]"   : 분류 묶음 제목 (3. 주요 성과)
- "1. 내용"    : 주요 업무 (분류 안에서 1. 2. …)
- "1) 소제목"  : 소제목 또는 진행 업무
- "한 일" / "할 일" : 기록 구분 제목 (단독 줄)
- "(1) 내용"  : 한 일·할 일 항목
- "① 내용"    : 번호 항목 (①②③… 순서)
- "- 내용"     : 하위 글머리
- "※ 내용"    : 작은 주석
- 그 외 줄     : 일반 문단

반드시 아래 JSON 하나만 출력 (코드블록·설명 금지):
{"summary":["보고요약 1","보고요약 2","보고요약 3"],
 "sections":[{"title":"1. 보고 개요","body":"..."},{"title":"2. 실적","body":"..."},{"title":"3. 주요 성과","body":"..."},{"title":"4. 진행 사항","body":"..."}]}
보고요약은 3~5개, 각 1~3문장.`;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  const sb = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const jwt = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  const { data: who } = await sb.auth.getUser(jwt);
  if (!who?.user) return json(401, { error: "unauthorized" });
  const { data: me } = await sb.from("profiles").select("role, active").eq("id", who.user.id).maybeSingle();
  if (!me?.active) return json(403, { error: "inactive" });

  let body: any;
  try { body = await req.json(); } catch { return json(400, { error: "bad_json" }); }

  if (body?.action === "status") return json(200, { enabled: !!API_KEY, model: API_KEY ? MODEL : null });

  if (body?.action !== "summarize") return json(400, { error: "unknown_action" });
  if (me.role !== "admin") return json(403, { error: "admin_only" });
  if (!API_KEY) return json(503, { error: "ai_not_configured" });

  const facts = JSON.stringify(body.facts ?? {});
  if (facts.length > MAX_INPUT) return json(413, { error: "too_large" });

  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: { "x-api-key": API_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json" },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: 4096,
      system: SYSTEM,
      messages: [{ role: "user", content: `다음 자료로 보고서를 작성하세요.\n${facts}` }],
    }),
  });
  if (!r.ok) {
    const detail = (await r.text()).slice(0, 300);
    return json(502, { error: "claude_failed", status: r.status, detail });
  }
  const out = await r.json();
  const text: string = (out.content ?? []).filter((c: any) => c.type === "text").map((c: any) => c.text).join("");
  const m = text.match(/\{[\s\S]*\}/);
  try {
    const parsed = JSON.parse(m ? m[0] : text);
    if (!Array.isArray(parsed.summary) || !Array.isArray(parsed.sections)) throw new Error("shape");
    return json(200, { ok: true, model: MODEL, result: parsed });
  } catch {
    return json(502, { error: "bad_ai_output" });
  }
});
