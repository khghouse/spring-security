
#### 시큐리티 인터페이스 구현 클래스
```text
* SecurityAuthenticationProvider -> AuthenticationProvider
* SecurityUserDetailsService -> UserDetailsService
* SecurityUser -> UserDetails
```

## 로그인 인증 흐름

1. 클라이언트로부터 로그인할 아이디와 비밀번호를 전달받는다.
2. 회원 인증
    1. 아이디에 해당하는 회원이 존재하는지 체크
    2. 비밀번호가 일치하는지 체크
3. 인증 객체 생성
    1. UsernamePasswordAuthenticationToken 초기 인증 객체 생성 (권한 정보 없음)
    2. SecurityAuthenticationProvider에 인증을 요청
        1. 초기 인증 토큰에서 Principal(접근 주체)의 아이디 추출
        2. SecurityUserDetailsService의 loadUserByUsername 메서드 호출
        3. 회원이 존재한다면 SecurityUser 객체를 생성하여 리턴 (권한 정보 포함)
4. JwtTokenProvider로 인증 객체를 전달하여 JWT 생성
    1. 인증 객체에서 권한 정보를 추출
    2. 액세스 토큰, 리프레쉬 토큰 생성
5. 리프레쉬 토큰을 레디스에 저장
