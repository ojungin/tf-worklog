// 로컬 실행용 예시입니다. 복사해서 web/config.js 로 저장하세요. (config.js 는 git에 올라가지 않습니다)
// GitHub Pages 배포 시에는 Actions가 저장소 Variables로 config.js 를 자동 생성합니다.
// anon(publishable) 키는 공개돼도 되는 키입니다. service_role 키는 절대 넣지 마세요.
window.TF_CONFIG = {
  url: "https://YOUR-PROJECT-REF.supabase.co",
  anonKey: "YOUR-ANON-OR-PUBLISHABLE-KEY",
  emailDomain: "tf-worklog.local"
};
