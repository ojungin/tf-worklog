-- 이전 버전이 만든 공용 이름 함수 정리.
-- is_active_member 는 TF 워크로그만 사용하던 함수라 삭제합니다(정책은 tf_is_active_member 로 교체됨).
-- is_admin 은 같은 프로젝트의 다른 서비스도 사용하므로 여기서 건드리지 않습니다.
drop function if exists public.is_active_member();
