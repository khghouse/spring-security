
## Spring Security
Spring Security와 JWT를 활용하여 REST API 환경에서 사용자 인증·인가 시스템을 구현한 프로젝트입니다.

<br />

### 기술 스택

| 카테고리 | 기술 |
|---------|------|
| **Backend** | Java 17, Spring Boot 3.2.4 |
| **Security** | Spring Security 6.2.3, JWT (jjwt) |
| **Database** | Spring Data JPA, H2 |
| **Build Tool** | Gradle 8.6 |
| **Testing** | JUnit 5, MockMvc |

<br />

#### 시큐리티 인터페이스 구현 클래스
```text
* SecurityAuthenticationProvider -> AuthenticationProvider
* SecurityUserDetailsService -> UserDetailsService
* SecurityUser -> UserDetails
```

### 로그인 인증 흐름

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

<br />

### 토큰 재발행 프로세스

1. 클라이언트로부터 액세스 토큰(만료 상태)과 리프레쉬 토큰을 전달받는다.
2. 리프레쉬 토큰 JWT 유효성 체크
3. 만료된 액세스 토큰에서 회원을 식별할 수 있는 정보 추출
4. 회원 정보 조회
5. 리프레쉬 토큰 비교
    1. 해당 회원의 리프레쉬 토큰을 레디스에서 조회
    2. 클라이언트로 전달받은 리프레쉬 토큰과 비교
6. 인증 객체 생성
    1. UsernamePasswordAuthenticationToken 초기 인증 객체 생성 (권한 정보 없음)
    2. SecurityAuthenticationProvider에 인증을 요청
        1. 초기 인증 토큰에서 Principal(접근 주체)의 아이디 추출
        2. SecurityUserDetailsService의 loadUserByUsername 메서드 호출
        3. 회원이 존재한다면 SecurityUser 객체를 생성하여 리턴 (권한 정보 포함)
7. JwtTokenProvider로 인증 객체를 전달하여 JWT 생성
    1. 인증 객체에서 권한 정보를 추출
    2. 액세스 토큰, 리프레쉬 토큰 생성
8. 리프레쉬 토큰을 레디스에 저장
9. 토큰 응답

<br />

### 로그아웃 프로세스

1. 요청 헤더를 통해 액세스 토큰을 전달받는다.
2. 액세스 토큰 JWT 유효성 체크
3. 액세스 토큰의 클레임 정보를 추출하여 인증 객체 생성
4. 인증 객체에서 회원 정보 추출
5. 해당 회원의 리프레쉬 토큰을 레디스에서 조회 및 삭제
6. 액세스 토큰을 레디스에 저장 → 블랙 리스트 처리

<br />

#### 참고 자료
- https://www.inflearn.com/course/호돌맨-요절복통-개발쇼
- https://suddiyo.tistory.com/entry/Spring-Spring-Security-JWT-로그인-구현하기-1
- https://velog.io/@wonizizi99/Spring-Jwt-방식-인증방식-Security-로그인-로그아웃
- https://hello-judy-world.tistory.com/216
- https://velog.io/@hiy7030/Spring-Spring-Security-%EA%B8%B0%EB%B3%B8-2-qdx7xe2j
- https://green-bin.tistory.com/73
- https://ailiartsua.tistory.com/25
- https://jhkimmm.tistory.com/29
