package com.example.springsecurity.provider;

import com.example.springsecurity.dto.response.JwtToken;
import com.example.springsecurity.dto.response.SecurityUser;
import com.example.springsecurity.entity.Member;
import com.example.springsecurity.enumeration.JwtErrorCode;
import com.example.springsecurity.exception.ForbiddenException;
import com.example.springsecurity.exception.JwtException;
import com.example.springsecurity.repository.MemberRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@Transactional
@ActiveProfiles("test")
class JwtTokenProviderTest {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private AuthenticationProvider authenticationProvider;

    @Autowired
    private MemberRepository memberRepository;

    @Test
    @DisplayName("토큰을 생성하고 액세스, 리프레쉬 토큰을 확인한다.")
    void generateToken() {
        // given
        Member member = Member.builder()
                .email("khghouse@daum.net")
                .password("Khghouse12!@")
                .build();
        memberRepository.save(member);

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken("khghouse@daum.net", null);
        Authentication authenticate = authenticationProvider.authenticate(authenticationToken);

        // when
        JwtToken result = jwtTokenProvider.generateToken(authenticate);

        // then
        assertThat(result).isNotNull();
        jwtTokenProvider.validateToken(result.getAccessToken());
        jwtTokenProvider.validateTokenByRefreshToken(result.getRefreshToken());
    }


    @Test
    @DisplayName("액세스 토큰으로 인증 객체를 리턴하고 확인한다.")
    void getAuthentication() {
        // given
        Member member = Member.builder()
                .email("khghouse@daum.net")
                .password("Khghouse12!@")
                .build();
        memberRepository.save(member);

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken("khghouse@daum.net", null);
        Authentication authenticate = authenticationProvider.authenticate(authenticationToken);
        JwtToken jwtToken = jwtTokenProvider.generateToken(authenticate);

        // when
        Authentication result = jwtTokenProvider.getAuthentication(jwtToken.getAccessToken());
        SecurityUser user = (SecurityUser) result.getPrincipal();

        // then
        assertThat(result.getName()).isEqualTo("khghouse@daum.net");
        assertThat(user.getEmail()).isEqualTo("khghouse@daum.net");
        assertThat(user.getMemberId()).isEqualTo(member.getId());
    }

    @Test
    @DisplayName("액세스 토큰으로 인증 객체를 리턴하지만 권한 정보가 없어서 예외가 발생한다.")
    void getAuthenticationNotAuthorized() {
        // given
        Member member = Member.builder()
                .email("khghouse@daum.net")
                .password("Khghouse12!@")
                .build();
        memberRepository.save(member);

        String accessToken = Jwts.builder()
                .subject("khghouse@daum.net")
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode("60VP+VFnf1cabbg8eVIv1JeVGjkPvVzk1fnHaKeUVqs=")))
                .claim("memberId", 1L)
                .claim("email", "khghouse@daum.net")
                .expiration(new Date(System.currentTimeMillis() + 3600L * 1000L))
                .compact();

        // when, then
        assertThatThrownBy(() -> jwtTokenProvider.getAuthentication(accessToken))
                .isInstanceOf(ForbiddenException.class)
                .hasMessage("권한 정보가 없는 토큰입니다.");
    }

    @Test
    @DisplayName("액세스 토큰을 이용하여 회원 ID를 조회한다.")
    void getMemberIdByAccessToken() {
        // given
        String accessToken = Jwts.builder()
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode("60VP+VFnf1cabbg8eVIv1JeVGjkPvVzk1fnHaKeUVqs=")))
                .claim("memberId", 1L)
                .expiration(new Date(System.currentTimeMillis() + 3600L * 1000L))
                .compact();

        // when
        Long result = jwtTokenProvider.getMemberIdByAccessToken(accessToken);

        // then
        assertThat(result).isEqualTo(1L);
    }

    @Test
    @DisplayName("만료된 액세스 토큰을 이용하여 회원 ID를 조회한다.")
    void getMemberIdByExpiredAccessToken() throws Exception {
        // given
        String accessToken = Jwts.builder()
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode("60VP+VFnf1cabbg8eVIv1JeVGjkPvVzk1fnHaKeUVqs=")))
                .claim("memberId", 1L)
                .expiration(new Date(System.currentTimeMillis() + 1000L))
                .compact();

        TimeUnit.SECONDS.sleep(1);

        // when
        Long result = jwtTokenProvider.getMemberIdByAccessToken(accessToken);

        // then
        assertThat(result).isEqualTo(1L);
    }

    @Test
    @DisplayName("액세스 토큰의 유효성을 검증하고 성공한다.")
    void validateToken() {
        // given
        String accessToken = Jwts.builder()
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode("60VP+VFnf1cabbg8eVIv1JeVGjkPvVzk1fnHaKeUVqs=")))
                .expiration(new Date(System.currentTimeMillis() + 3600L * 1000L))
                .compact();

        // when
        boolean result = jwtTokenProvider.validateToken(accessToken);

        // then
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("액세스 토큰의 유효성 체크에서 손상된 토큰으로 예외가 발생한다.")
    void validateTokenMalformedJwtException() {
        // when, then
        assertThatThrownBy(() -> jwtTokenProvider.validateToken("json.web.token"))
                .isInstanceOf(JwtException.class)
                .satisfies(e -> {
                    JwtException jwtException = (JwtException) e;
                    assertThat(jwtException.getJwtErrorCode()).isEqualTo(JwtErrorCode.MALFORMED);
                });
    }

    @Test
    @DisplayName("액세스 토큰의 유효성 체크에서 만료된 토큰으로 예외가 발생한다.")
    void validateTokenExpiredJwtException() throws Exception {
        // given
        String accessToken = Jwts.builder()
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode("60VP+VFnf1cabbg8eVIv1JeVGjkPvVzk1fnHaKeUVqs=")))
                .expiration(new Date(System.currentTimeMillis() + 1000L))
                .compact();

        TimeUnit.SECONDS.sleep(1);

        // when, then
        assertThatThrownBy(() -> jwtTokenProvider.validateToken(accessToken))
                .isInstanceOf(JwtException.class)
                .satisfies(e -> {
                    JwtException jwtException = (JwtException) e;
                    assertThat(jwtException.getJwtErrorCode()).isEqualTo(JwtErrorCode.EXPIRED);
                });
    }

    @Test
    @DisplayName("다른 키 값으로 생성된 액세스 토큰은 유효성 체크에서 예외가 발생한다.")
    void validateTokenInvalidKey() {
        // given
        String accessToken = Jwts.builder()
                .signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode("yXbYyWTRsYQwoe6Tm+z5ujQ/Irmi34d3QEzJQAxuRwQ=")))
                .expiration(new Date(System.currentTimeMillis() + 3600L * 1000L))
                .compact();

        // when, then
        assertThatThrownBy(() -> jwtTokenProvider.validateToken(accessToken))
                .isInstanceOf(JwtException.class)
                .satisfies(e -> {
                    JwtException jwtException = (JwtException) e;
                    assertThat(jwtException.getJwtErrorCode()).isEqualTo(JwtErrorCode.INVALID);
                });
    }

}