# 닥터빌 TF 워크로그

TF 업무 관리용 웹앱입니다. 화면은 **GitHub Pages**에서 서비스하고, 데이터는 **Supabase**에 암호문으로 저장합니다.

- **잡스케줄러**: 달력에서 한 일 / 할 일 등록, 기한 지난 할 일 표시
- **업무 Report**: 주간·월간, 담당자별 정리, 업무 단위 코멘트(작성자·일시 기록)
- **회의록 로그**: 회의록 작성·검색, 회의록별 코멘트
- **보고서**: 기간을 정하면 업무 Report·회의록을 모아 '보고의 건' 양식 초안 생성 → 화면에서 수정·저장, Word(.docx) 다운로드. 저장 이력은 별도 기록(본문·Word에는 미포함). 관리자 생성, 전원 열람·수정
- **관리자**: 계정 추가·권한·비활성화·비밀번호 초기화·삭제, 업무ID·회의록 관리

## 저장소 구성

```
web/                         GitHub Pages로 배포되는 정적 웹앱
  index.html
  assets/app.js, app.css
  (supabase-js 2.45.4 는 jsDelivr CDN에서 무결성 해시(SRI)로 검증해 로드)
  config.example.js          로컬 실행용 설정 예시 (배포 시 config.js 자동 생성)
supabase/
  migrations/…_init.sql      테이블 · RLS 보안정책 · 실시간 설정
  functions/admin-users/     계정 관리 Edge Function
  config.toml
.github/workflows/
  deploy.yml                 Supabase(DB·함수) 적용 후 GitHub Pages 배포
```

## 보안 구조

| 구분 | 방식 |
|---|---|
| 암호화 | 업무·회의록·코멘트·이름을 **브라우저에서 AES-256-GCM 암호화** 후 전송. Supabase에는 암호문만 저장 |
| 키 관리 | 워크스페이스 키를 사용자별 비밀번호 파생키(PBKDF2 25만 회)로 감싸 저장. 비밀번호 원문은 어디에도 저장하지 않음 |
| 로그인 | 아이디 + 비밀번호 (Supabase Auth). 회원가입 차단, 계정은 관리자만 생성 |
| 권한 | DB 행 단위 보안(RLS): 본인 업무만 수정, 관리자는 전체 수정·삭제, 비활성 계정 조회 차단 |
| 웹 보안 | CSP로 스크립트를 자체 파일·고정 버전 CDN(SRI 검증)으로만 제한, 외부 통신은 Supabase로만 허용 |
| 저장소 | 비밀 값은 코드에 없음. Supabase 키·토큰은 GitHub Actions Variables / Secrets로 주입 |

평문으로 남는 값은 접근제어에 필요한 항목뿐입니다: 아이디, 권한, 활성 여부, 작성자 ID, 업무ID/회의록ID, 생성·수정 시각.

## 설치 순서

### 1) Supabase 프로젝트 준비
1. https://supabase.com 에서 새 프로젝트 생성 (Region: **Northeast Asia (Seoul)** 권장). DB 비밀번호를 보관해 둡니다.
2. 프로젝트를 TF 전용으로 쓴다면 Variables에 `DISABLE_SIGNUP=true`를 넣어 공개 회원가입을 막으세요. 다른 서비스와 공유하는 프로젝트라면 넣지 않습니다(회원가입이 열려 있어도 TF 계정이 아니면 RLS로 데이터 접근이 차단됩니다).

### 2) GitHub 저장소 만들기
1. 새 저장소 생성(예: `tf-worklog`) 후 이 폴더 내용을 올립니다.
2. **Settings → Pages → Build and deployment → Source: GitHub Actions** 선택.

> GitHub 무료 플랜은 **public 저장소**에서만 Pages를 쓸 수 있습니다. private 저장소는 Team/Enterprise 플랜이 필요합니다.
> Pages 사이트 주소는 인터넷에 공개되므로, 데이터 보호는 로그인 + 암호화 + RLS가 담당합니다.

### 3) GitHub Actions 값 등록
**Settings → Secrets and variables → Actions**

| 종류 | 이름 | 값 |
|---|---|---|
| Variables | `SUPABASE_PROJECT_REF` | Supabase 프로젝트 REF (`https://<REF>.supabase.co`의 REF) |
| Secrets | `SUPABASE_ACCESS_TOKEN` | supabase.com → Account → Access Tokens에서 발급 |
| Secrets | `SETUP_TOKEN` | 최초 관리자 생성용 암호문구(직접 정함). 관리자 생성 후 삭제 |
| Variables(선택) | `TF_EMAIL_DOMAIN` / `ALLOWED_ORIGIN` | 기본값 `tf-worklog.local` / `https://<계정>.github.io` |

Supabase URL·공개 키(anon/publishable)는 배포 때 자동으로 읽어 오므로 따로 넣지 않습니다. **service_role 키는 어디에도 등록하지 않습니다.**

### 4) 배포 실행
**Actions → Deploy (Supabase + GitHub Pages) → Run workflow**. 한 번에 다음을 수행합니다.
- DB 테이블·보안정책(RLS) 적용 (`DISABLE_SIGNUP=true`일 때만 공개 회원가입 차단)
- 계정관리 Edge Function 배포와 Secret 설정
- 웹앱을 GitHub Pages에 배포 (완료 화면에 접속 주소 표시)

이후 `main`에 push 하면 자동 재배포됩니다.

### 5) 최초 관리자 생성
웹앱 접속 → **최초 관리자 계정 만들기** 화면에서 `SETUP_TOKEN`·아이디·이름·비밀번호 입력 →
생성 후 GitHub Secrets에서 **`SETUP_TOKEN` 삭제 → 워크플로 재실행**(Supabase 쪽 토큰도 자동 제거) → **관리자** 탭에서 팀원 계정 추가.

## 보고서 Claude AI 요약 켜기 (선택)
1. console.anthropic.com 에서 API 키 발급 (사용량 과금)
2. GitHub **Secrets**에 `ANTHROPIC_API_KEY` 등록, 필요 시 **Variables**에 `TF_CLAUDE_MODEL`(기본 `claude-sonnet-4-5`)
3. Actions에서 Deploy 재실행 → 보고서 편집 화면의 **Claude AI 요약** 버튼이 켜짐

요약 시 해당 기간의 업무·회의록 내용이 복호화되어 Supabase 함수를 거쳐 Claude API로 전송됩니다(저장하지 않음). 사내 승인 범위를 확인한 뒤 켜세요.

## 로컬 실행 (선택)
```bash
cp web/config.example.js web/config.js   # 값 입력
cd web && python3 -m http.server 8080    # http://localhost:8080
```
로컬에서 쓰려면 Supabase Secrets의 `ALLOWED_ORIGIN`을 비워 두거나 로컬 주소로 잠시 바꿔야 계정관리 기능이 동작합니다.

## 운영 시 유의사항
- **모든 관리자 비밀번호를 잃으면 데이터를 복구할 수 없습니다.** 관리자 계정을 2개 이상 유지하세요.
- 일반 사용자 비밀번호 분실 시 관리자가 **비밀번호 초기화**로 재발급합니다.
- 비활성화한 계정은 로그인·조회가 즉시 차단됩니다. 퇴사자는 비활성화 후 필요 시 삭제하세요.
- Supabase 백업도 암호문이므로 백업만으로는 내용을 열람할 수 없습니다.
- Supabase 커스텀 도메인을 쓰는 경우 `web/index.html`의 CSP `connect-src`에 해당 도메인을 추가하세요.
- 회의록에 전략·계약·개인정보가 포함될 경우 사내 정책에 따라 입력 전 승인 절차를 거치세요.
