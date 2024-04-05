package com.example.springsecurity.service;

import com.example.springsecurity.dto.request.AuthServiceRequest;
import com.example.springsecurity.dto.response.JwtToken;
import com.example.springsecurity.entity.Member;
import com.example.springsecurity.provider.JwtTokenProvider;
import com.example.springsecurity.repository.MemberRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationProvider authenticationProvider;

    @Transactional
    public void signup(AuthServiceRequest request) {
        validateAlreadyJoinedMember(request.getEmail());

        memberRepository.save(request.toEntity(passwordEncoder.encode(request.getPassword())));
    }

    public JwtToken login(AuthServiceRequest request) {
        Member member = memberRepository.findByEmailAndDeletedFalse(request.getEmail())
                .orElseThrow(() -> new RuntimeException("존재하지 않는 계정입니다."));

        if (!passwordEncoder.matches(request.getPassword(), member.getPassword())) {
            throw new RuntimeException("아이디와 비밀번호를 다시 확인해 주세요.");
        }

        return generateToken(member);
    }

    /**
     * 리프레쉬 토큰을 이용하여 토큰을 재발행한다.
     */
    public JwtToken reissueToken(HttpServletRequest request) {
        String refreshToken = jwtTokenProvider.resolveToken(request);

        if (refreshToken == null || !jwtTokenProvider.validateTokenByRefreshToken(refreshToken)) {
            throw new RuntimeException("인증 정보가 유효하지 않습니다.");
        }

        Long memberId = jwtTokenProvider.getMemberIdByRefreshToken(refreshToken);
        Member member = memberRepository.findByIdAndDeletedFalse(memberId)
                .orElseThrow(() -> new RuntimeException("존재하지 않는 계정입니다."));

        return generateToken(member);
    }

    /**
     * 인증 정보를 담고 있는 JWT 액세스 토큰을 생성한다.
     */
    private JwtToken generateToken(Member member) {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(member.getEmail(), null);
        Authentication authenticate = authenticationProvider.authenticate(authenticationToken);
        return jwtTokenProvider.generateToken(authenticate);
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
