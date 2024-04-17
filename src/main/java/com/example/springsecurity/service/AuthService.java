package com.example.springsecurity.service;

import com.example.springsecurity.dto.request.AuthServiceRequest;
import com.example.springsecurity.dto.request.ReissueServiceRequest;
import com.example.springsecurity.dto.response.JwtToken;
import com.example.springsecurity.dto.response.SecurityUser;
import com.example.springsecurity.entity.Member;
import com.example.springsecurity.exception.BusinessException;
import com.example.springsecurity.provider.JwtTokenProvider;
import com.example.springsecurity.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private final String PREFIX_REDIS_KEY_REFRESH_TOKEN = "refreshToken:";

    private final MemberRepository memberRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationProvider authenticationProvider;
    private final PasswordEncoder passwordEncoder;
    private final RedisTemplate redisTemplate;

    /**
     * 회원 가입
     */
    @Transactional
    public void signup(AuthServiceRequest request) {
        validateAlreadyJoinedMember(request.getEmail());
        String encryptedPassword = passwordEncoder.encode(request.getPassword());
        memberRepository.save(request.toEntity(encryptedPassword));
    }

    /**
     * 로그인
     */
    public JwtToken login(AuthServiceRequest request) {
        Member member = memberRepository.findByEmailAndDeletedFalse(request.getEmail())
                .orElseThrow(() -> new BusinessException("존재하지 않는 계정입니다."));

        if (!passwordEncoder.matches(request.getPassword(), member.getPassword())) {
            throw new BusinessException("아이디와 비밀번호를 다시 확인해 주세요.");
        }

        // 토큰 생성
        JwtToken jwtToken = generateToken(member);

        // 리프레쉬 토큰을 레디스에 저장
        // .set(key, value, now() + TimeUnit Value, TimeUnit)
        redisTemplate.opsForValue()
                .set(PREFIX_REDIS_KEY_REFRESH_TOKEN + member.getId(), jwtToken.getRefreshToken(), jwtToken.getRefreshTokenExpirationSeconds(), TimeUnit.SECONDS);

        return jwtToken;
    }

    /**
     * 리프레쉬 토큰을 이용하여 토큰을 재발행한다.
     */
    public JwtToken reissueToken(ReissueServiceRequest request) {
        String refreshToken = request.getRefreshToken();
        if (!jwtTokenProvider.validateTokenByRefreshToken(refreshToken)) {
            throw new RuntimeException("인증 정보가 유효하지 않습니다.");
        }

        Long memberId = jwtTokenProvider.getMemberIdByAccessToken(request.getAccessToken());
        Member member = memberRepository.findByIdAndDeletedFalse(memberId)
                .orElseThrow(() -> new RuntimeException("존재하지 않는 계정입니다."));

        ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();
        String redisRefreshToken = valueOperations.get(PREFIX_REDIS_KEY_REFRESH_TOKEN + member.getId());

        if (!refreshToken.equals(redisRefreshToken)) {
            throw new RuntimeException("인증 정보가 유효하지 않습니다.");
        }

        JwtToken jwtToken = generateToken(member);
        valueOperations.set(PREFIX_REDIS_KEY_REFRESH_TOKEN + member.getId(), jwtToken.getRefreshToken(), jwtToken.getRefreshTokenExpirationSeconds(), TimeUnit.SECONDS);

        return jwtToken;
    }

    /**
     * 로그아웃
     */
    public void logout(String accessToken) {
        if (!jwtTokenProvider.validateToken(accessToken)) {
            throw new RuntimeException("인증 정보가 유효하지 않습니다.");
        }

        Authentication authentication = jwtTokenProvider.getAuthentications(accessToken);
        SecurityUser member = (SecurityUser) authentication.getPrincipal();

        ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();
        if (valueOperations.get(PREFIX_REDIS_KEY_REFRESH_TOKEN + member.getMemberId()) != null) {
            redisTemplate.delete(PREFIX_REDIS_KEY_REFRESH_TOKEN + member.getMemberId());
        }

        valueOperations.set(accessToken, "logout");
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
