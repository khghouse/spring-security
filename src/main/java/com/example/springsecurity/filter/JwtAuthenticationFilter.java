package com.example.springsecurity.filter;


import com.example.springsecurity.component.Redis;
import com.example.springsecurity.provider.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;
import java.util.Optional;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends GenericFilterBean {

    private final JwtTokenProvider jwtTokenProvider;
    private final Redis redis;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        // 1. Request 객체로부터 헤더에 포함된 액세스 토큰을 추출
        String token = jwtTokenProvider.resolveToken((HttpServletRequest) request);

        // 2. JWT 유효성 체크
        if (token != null && jwtTokenProvider.validateToken(token)) {
            // 3. 해당 액세스 토큰으로 레디스를 조회하여 로그아웃된 토큰인지 체크
            String status = Optional.ofNullable(redis.get(token))
                    .map(String::valueOf)
                    .orElse(null);

            if (!"logout".equals(status)) {
                // 4. 액세스 토큰에 포함된 클레임 정보를 이용하여 Authentication 객체 생성 및 시큐리티 컨텍스트에 저장
                Authentication authentication = jwtTokenProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        chain.doFilter(request, response);
    }

}
