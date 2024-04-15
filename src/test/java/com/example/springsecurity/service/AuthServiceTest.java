package com.example.springsecurity.service;

import com.example.springsecurity.dto.request.AuthServiceRequest;
import com.example.springsecurity.dto.request.ReissueServiceRequest;
import com.example.springsecurity.dto.response.JwtToken;
import com.example.springsecurity.entity.Member;
import com.example.springsecurity.provider.JwtTokenProvider;
import com.example.springsecurity.repository.MemberRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@Transactional
@ActiveProfiles("test")
class AuthServiRceTest {

    private final String PREFIX_REDIS_KEY_REFRESH_TOKEN = "refreshToken:";

    @Autowired
    private AuthService authService;

    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private AuthenticationProvider authenticationProvider;

    @Autowired
    private RedisTemplate redisTemplate;

    @Test
    @DisplayName("회원 가입에 성공한다.")
    void signup() {
        // given
        AuthServiceRequest request = AuthServiceRequest.builder()
                .email("khghouse@daum.net")
                .password("password12#$")
                .build();

        // when
        authService.signup(request);

        // then
        Member result = memberRepository.findByEmail("khghouse@daum.net").get();
        assertThat(result).isNotNull();
    }

    @Test
    @DisplayName("회원 가입을 시도했지만 이미 가입된 회원으로 예외가 발생한다.")
    void signupAlreadyJoinedMember() {
        // given
        Member member = Member.builder()
                .email("khghouse@daum.net")
                .password("password12#$")
                .deleted(false)
                .build();

        memberRepository.save(member);

        AuthServiceRequest request = AuthServiceRequest.builder()
                .email("khghouse@daum.net")
                .password("password12#$")
                .build();

        // when, then
        assertThatThrownBy(() -> authService.signup(request))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("이미 가입된 이메일입니다.");
    }

    @Test
    @DisplayName("이미 가입된 회원이면 로그인에 성공한다.")
    void login() {
        // given
        Member member = Member.builder()
                .email("khghouse@daum.net")
                .password(passwordEncoder.encode("password12#$"))
                .deleted(false)
                .build();

        memberRepository.save(member);

        AuthServiceRequest request = AuthServiceRequest.builder()
                .email("khghouse@daum.net")
                .password("password12#$")
                .build();

        // when
        JwtToken result = authService.login(request);

        // then
        assertThat(result).isNotNull();
    }

    @Test
    @DisplayName("존재하지 않는 계정으로 로그인하면 예외가 발생한다.")
    void loginNotExistMember() {
        // given
        AuthServiceRequest request = AuthServiceRequest.builder()
                .email("khghouse@daum.net")
                .password("password12#$")
                .build();

        // when, then
        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("존재하지 않는 계정입니다.");
    }

    @Test
    @DisplayName("이미 가입된 회원이지만 비밀번호가 틀려 예외가 발생한다.")
    void loginInvalidData() {
        // given
        Member member = Member.builder()
                .email("khghouse@daum.net")
                .password(passwordEncoder.encode("password12#$"))
                .deleted(false)
                .build();

        memberRepository.save(member);

        AuthServiceRequest request = AuthServiceRequest.builder()
                .email("khghouse@daum.net")
                .password("password123#$")
                .build();

        // when, then
        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("아이디와 비밀번호를 다시 확인해 주세요.");
    }

    @Test
    @DisplayName("토큰을 이용하여 토큰을 재발행한다.")
    void reissueToken() {
        // given
        Member member = Member.builder()
                .email("khghouse@daum.net")
                .password(passwordEncoder.encode("password12#$"))
                .deleted(false)
                .build();

        memberRepository.save(member);

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken("khghouse@daum.net", null);
        Authentication authenticate = authenticationProvider.authenticate(authenticationToken);
        JwtToken jwtToken = jwtTokenProvider.generateToken(authenticate);

        redisTemplate.opsForValue()
                .set(PREFIX_REDIS_KEY_REFRESH_TOKEN + member.getId(), jwtToken.getRefreshToken(), jwtToken.getRefreshTokenExpirationSeconds(), TimeUnit.SECONDS);

        ReissueServiceRequest request = ReissueServiceRequest.builder()
                .accessToken(jwtToken.getAccessToken())
                .refreshToken(jwtToken.getRefreshToken())
                .build();

        // when
        JwtToken result = authService.reissueToken(request);

        // then
        assertThat(result.getAccessToken()).isNotNull();
        assertThat(result.getRefreshToken()).isNotNull();
    }

    @Test
    @DisplayName("토큰을 재발행하지만 존재하지 않는 계정으로 예외가 발생한다.")
    void reissueTokenNotExistMember() {
        // given
        Member member = Member.builder()
                .email("khghouse@daum.net")
                .password(passwordEncoder.encode("password12#$"))
                .deleted(false)
                .build();

        memberRepository.save(member);

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken("khghouse@daum.net", null);
        Authentication authenticate = authenticationProvider.authenticate(authenticationToken);
        JwtToken jwtToken = jwtTokenProvider.generateToken(authenticate);

        memberRepository.delete(member);

        redisTemplate.opsForValue()
                .set(PREFIX_REDIS_KEY_REFRESH_TOKEN + "1", jwtToken.getRefreshToken(), jwtToken.getRefreshTokenExpirationSeconds(), TimeUnit.SECONDS);

        ReissueServiceRequest request = ReissueServiceRequest.builder()
                .accessToken(jwtToken.getAccessToken())
                .refreshToken(jwtToken.getRefreshToken())
                .build();

        // when, Then
        assertThatThrownBy(() -> authService.reissueToken(request))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("존재하지 않는 계정입니다.");
    }

    @Test
    @DisplayName("토큰을 재발행하지만 유효하지 않은 토큰으로 예외가 발생한다.")
    void reissueTokenInvalid() {
        // given
        ReissueServiceRequest request = ReissueServiceRequest.builder()
                .accessToken("json.web.token")
                .refreshToken("json.web.token")
                .build();

        // when, Then
        assertThatThrownBy(() -> authService.reissueToken(request))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("인증 정보가 유효하지 않습니다.");
    }

    @Test
    @DisplayName("로그아웃하면 레디스에 저장된 액세스 토큰은 logout이 되고, 리프레쉬 토큰은 삭제된다.")
    void logout() {
        // given
        Member member = Member.builder()
                .email("khghouse@daum.net")
                .password(passwordEncoder.encode("password12#$"))
                .deleted(false)
                .build();

        memberRepository.save(member);

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken("khghouse@daum.net", null);
        Authentication authenticate = authenticationProvider.authenticate(authenticationToken);
        JwtToken jwtToken = jwtTokenProvider.generateToken(authenticate);

        redisTemplate.opsForValue()
                .set(PREFIX_REDIS_KEY_REFRESH_TOKEN + member.getId(), jwtToken.getRefreshToken(), jwtToken.getRefreshTokenExpirationSeconds(), TimeUnit.SECONDS);

        String accessToken = jwtToken.getAccessToken();

        // when
        authService.logout(accessToken);

        // then
        assertThat(redisTemplate.opsForValue().get(accessToken)).isEqualTo("logout");
        assertThat(redisTemplate.opsForValue().get(PREFIX_REDIS_KEY_REFRESH_TOKEN + member.getId())).isNull();
    }

    @Test
    @DisplayName("유효하지 않는 토큰으로 로그아웃을 시도하면 예외가 발생한다.")
    void logoutInvalidToken() {
        // given
        String accessToken = "json.web.token";

        // when, Then
        assertThatThrownBy(() -> authService.logout(accessToken))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("인증 정보가 유효하지 않습니다.");
    }

}