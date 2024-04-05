package com.example.springsecurity.service;

import com.example.springsecurity.dto.request.AuthServiceRequest;
import com.example.springsecurity.dto.response.JwtToken;
import com.example.springsecurity.entity.Member;
import com.example.springsecurity.repository.MemberRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@Transactional
@ActiveProfiles("test")
class AuthServiceTest {

    @Autowired
    private AuthService authService;

    @Autowired
    private MemberRepository memberRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

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

}