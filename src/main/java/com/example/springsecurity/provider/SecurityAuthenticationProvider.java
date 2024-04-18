package com.example.springsecurity.provider;

import com.example.springsecurity.dto.response.SecurityUser;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;

@Configuration
@RequiredArgsConstructor
public class SecurityAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            throw new RuntimeException("인증 정보가 유효하지 않습니다.");
        }

        // 초기 인증 토큰에서 Principal(접근 주체)의 아이디 추출
        String email = authentication.getPrincipal()
                .toString();

        // SecurityUserDetailsService의 loadUserByUsername 메서드 호출
        SecurityUser securityUser = (SecurityUser) userDetailsService.loadUserByUsername(email);

        // 회원이 존재한다면 SecurityUser 객체를 생성하여 리턴 (권한 정보 포함)
        return new UsernamePasswordAuthenticationToken(securityUser, null, securityUser.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
    }

}
