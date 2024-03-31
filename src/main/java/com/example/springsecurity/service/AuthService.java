package com.example.springsecurity.service;

import com.example.springsecurity.dto.request.AuthServiceRequest;
import com.example.springsecurity.dto.response.AuthResponse;
import com.example.springsecurity.entity.Member;
import com.example.springsecurity.provider.JwtTokenProvider;
import com.example.springsecurity.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationProvider authenticationProvider;

    public AuthResponse signup(AuthServiceRequest request) {
        validateAlreadyJoinedMember(request.getEmail());

        Member member = memberRepository.save(request.toEntity(passwordEncoder.encode(request.getPassword())));

        return AuthResponse.of(generateAccessToken(member));
    }

    public AuthResponse login(AuthServiceRequest request) {
        Member member = memberRepository.findByEmailAndDeletedFalse(request.getEmail())
                .orElseThrow(() -> new RuntimeException("존재하지 않는 계정입니다."));

        if (!passwordEncoder.matches(request.getPassword(), member.getPassword())) {
            throw new RuntimeException("아이디와 비밀번호를 다시 확인해 주세요.");
        }

        return AuthResponse.of(generateAccessToken(member));
    }

    /**
     * 인증 정보를 담고 있는 JWT 액세스 토큰을 생성한다.
     */
    private String generateAccessToken(Member member) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(member.getEmail(), null);
        Authentication authenticate = authenticationProvider.authenticate(authenticationToken);
        String accessToken = jwtTokenProvider.generateAccessToken(authenticate);
        return accessToken;
    }

    /**
     * 이미 가입된 회원인지 체크 by email
     */
    private void validateAlreadyJoinedMember(String email) {
        Optional<Member> optMember = memberRepository.findByEmailAndDeletedFalse(email);

        if (optMember.isPresent()) {
            throw new RuntimeException("이미 가입된 이메일입니다.");
        }
    }

}
