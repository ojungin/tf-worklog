// 닥터빌 TF 워크로그 — 계정 관리 Edge Function
// 배포: supabase functions deploy admin-users --no-verify-jwt
//  (호출자 인증은 아래 코드에서 직접 검증합니다)
// 필요한 Secret: TF_SETUP_TOKEN (최초 관리자 생성용 일회성 토큰), TF_EMAIL_DOMAIN(선택), TF_ALLOWED_ORIGIN(선택)
// (다른 서비스와 같은 Supabase 프로젝트를 공유해도 충돌하지 않도록 TF_ 접두어 사용)
// SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY 는 Supabase가 자동 주입합니다.

import { createClient } from "jsr:@supabase/supabase-js@2";

const ALLOWED_ORIGIN = Deno.env.get("TF_ALLOWED_ORIGIN") ?? "*"; // 운영 시 페이지 도메인으로 제한 권장
const cors = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

const DOMAIN = Deno.env.get("TF_EMAIL_DOMAIN") ?? "tf-worklog.local";
const USERNAME_RE = /^[A-Za-z0-9._-]{3,30}$/;
const emailOf = (u: string) => `${u.toLowerCase()}@${DOMAIN}`;

type Enc = { iv: string; ct: string };
type Wrap = { salt: string; iter: number; wk: Enc };
const isEnc = (o: any): o is Enc => o && typeof o.iv === "string" && typeof o.ct === "string" && o.ct.length < 400_000;
const isWrap = (o: any): o is Wrap => o && typeof o.salt === "string" && Number.isInteger(o.iter) && o.iter >= 100000 && isEnc(o.wk);
const okPw = (p: unknown) => typeof p === "string" && p.length >= 8 && p.length <= 128;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

  const sb = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  let body: any;
  try { body = await req.json(); } catch { return json(400, { error: "bad_json" }); }
  const action = body?.action;

  // ---------- 최초 관리자 생성 ----------
  if (action === "bootstrap") {
    const token = Deno.env.get("TF_SETUP_TOKEN");
    if (!token || body.token !== token) return json(403, { error: "invalid_setup_token" });
    const { count } = await sb.from("profiles").select("id", { count: "exact", head: true });
    const { data: ws } = await sb.from("workspace").select("id").maybeSingle();
    if ((count ?? 0) > 0 || ws) return json(409, { error: "already_initialized" });
    const { username, password, name_enc, wrap, check_enc } = body;
    if (!USERNAME_RE.test(username ?? "") || !okPw(password) || !isEnc(name_enc) || !isWrap(wrap) || !isEnc(check_enc))
      return json(400, { error: "invalid_input" });
    const { data: cu, error: e1 } = await sb.auth.admin.createUser({ email: emailOf(username), password, email_confirm: true });
    if (e1 || !cu.user) return json(400, { error: "create_failed", detail: e1?.message });
    const uid = cu.user.id;
    const r1 = await sb.from("profiles").insert({ id: uid, username, name_enc, role: "admin" });
    const r2 = r1.error ? r1 : await sb.from("key_wraps").insert({ user_id: uid, ...wrap });
    const r3 = r2.error ? r2 : await sb.from("workspace").insert({ id: 1, check_enc });
    if (r3.error) { await sb.auth.admin.deleteUser(uid); await sb.from("workspace").delete().eq("id", 1); return json(500, { error: "db_failed", detail: r3.error.message }); }
    return json(200, { ok: true });
  }

  // ---------- 이하: 로그인한 사용자만 ----------
  const jwt = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  const { data: who, error: we } = await sb.auth.getUser(jwt);
  if (we || !who?.user) return json(401, { error: "unauthorized" });
  const callerId = who.user.id;
  const { data: caller } = await sb.from("profiles").select("id, role, active").eq("id", callerId).maybeSingle();
  if (!caller || !caller.active) return json(403, { error: "inactive" });

  // 본인 비밀번호 변경 (키 재포장 + 인증 비밀번호 변경)
  if (action === "self_password") {
    const { password, wrap } = body;
    if (!okPw(password) || !isWrap(wrap)) return json(400, { error: "invalid_input" });
    const { data: old } = await sb.from("key_wraps").select("*").eq("user_id", callerId).single();
    const u1 = await sb.from("key_wraps").update({ ...wrap, updated_at: new Date().toISOString() }).eq("user_id", callerId);
    if (u1.error) return json(500, { error: "db_failed" });
    const { error } = await sb.auth.admin.updateUserById(callerId, { password });
    if (error) { if (old) await sb.from("key_wraps").update(old).eq("user_id", callerId); return json(400, { error: "password_failed", detail: error.message }); }
    return json(200, { ok: true });
  }

  if (caller.role !== "admin") return json(403, { error: "admin_only" });

  const target: string | undefined = body.user_id;

  switch (action) {
    case "create": {
      const { username, password, name_enc, wrap, role } = body;
      if (!USERNAME_RE.test(username ?? "") || !okPw(password) || !isEnc(name_enc) || !isWrap(wrap) || !["admin", "user"].includes(role))
        return json(400, { error: "invalid_input" });
      const { data: dup } = await sb.from("profiles").select("id").ilike("username", username).maybeSingle();
      if (dup) return json(409, { error: "username_taken" });
      const { data: cu, error } = await sb.auth.admin.createUser({ email: emailOf(username), password, email_confirm: true });
      if (error || !cu.user) return json(400, { error: "create_failed", detail: error?.message });
      const uid = cu.user.id;
      const r1 = await sb.from("profiles").insert({ id: uid, username, name_enc, role });
      const r2 = r1.error ? r1 : await sb.from("key_wraps").insert({ user_id: uid, ...wrap });
      if (r2.error) { await sb.auth.admin.deleteUser(uid); return json(500, { error: "db_failed", detail: r2.error.message }); }
      return json(200, { ok: true, id: uid });
    }
    case "reset_password": {
      const { password, wrap } = body;
      if (!target || !okPw(password) || !isWrap(wrap)) return json(400, { error: "invalid_input" });
      const { error } = await sb.auth.admin.updateUserById(target, { password });
      if (error) return json(400, { error: "password_failed", detail: error.message });
      const r = await sb.from("key_wraps").upsert({ user_id: target, ...wrap, updated_at: new Date().toISOString() });
      if (r.error) return json(500, { error: "db_failed" });
      return json(200, { ok: true });
    }
    case "set_role": {
      const role = body.role;
      if (!target || !["admin", "user"].includes(role)) return json(400, { error: "invalid_input" });
      if (target === callerId) return json(400, { error: "cannot_change_self" });
      const r = await sb.from("profiles").update({ role }).eq("id", target);
      if (r.error) return json(500, { error: "db_failed" });
      return json(200, { ok: true });
    }
    case "set_active": {
      const active = body.active === true;
      if (!target) return json(400, { error: "invalid_input" });
      if (target === callerId) return json(400, { error: "cannot_change_self" });
      const r = await sb.from("profiles").update({ active }).eq("id", target);
      if (r.error) return json(500, { error: "db_failed" });
      // 비활성 계정은 인증 단계에서도 로그인 차단
      await sb.auth.admin.updateUserById(target, { ban_duration: active ? "none" : "876000h" });
      return json(200, { ok: true });
    }
    case "set_name": {
      if (!target || !isEnc(body.name_enc)) return json(400, { error: "invalid_input" });
      const r = await sb.from("profiles").update({ name_enc: body.name_enc }).eq("id", target);
      if (r.error) return json(500, { error: "db_failed" });
      return json(200, { ok: true });
    }
    case "delete": {
      if (!target) return json(400, { error: "invalid_input" });
      if (target === callerId) return json(400, { error: "cannot_change_self" });
      const { error } = await sb.auth.admin.deleteUser(target); // profiles·key_wraps 연쇄 삭제, 작성 글은 유지
      if (error) return json(400, { error: "delete_failed", detail: error.message });
      return json(200, { ok: true });
    }
    default:
      return json(400, { error: "unknown_action" });
  }
});
