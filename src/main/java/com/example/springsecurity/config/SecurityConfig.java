package com.example.springsecurity.config;

import com.example.springsecurity.component.Redis;
import com.example.springsecurity.filter.JwtAuthenticationFilter;
import com.example.springsecurity.handler.SecurityAccessDeniedHandler;
import com.example.springsecurity.provider.JwtTokenProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.boot.autoconfigure.security.servlet.PathRequest.toH2Console;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final JwtTokenProvider jwtTokenProvider;
    private final Redis redis;
    private final ObjectMapper objectMapper;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity.csrf(AbstractHttpConfigurer::disable) // REST API 환경에서 JWT 토큰으로 인증 -> 비활성화
                .httpBasic(AbstractHttpConfigurer::disable) // Bearer 토큰 인증 방식 사용 -> 비활성화
                .formLogin(AbstractHttpConfigurer::disable) // json 데이터를 통한 로그인 -> 비활성화
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션을 사용하지 않음
                .authorizeHttpRequests((authorize) -> authorize // 요청에 대한 인가 규칙 정의
                        .requestMatchers("/auth/**").permitAll() // 해당 API는 인증, 인가 없이 접근 허용
                        .requestMatchers(HttpMethod.POST, "/example").permitAll() // 해당 API는 POST 메서드만 인증, 인가 없이 접근 허용
                        .requestMatchers("/user").hasRole("USER") // 해당 API는 USER 권한이 필요
                        .requestMatchers("/admin").hasRole("ADMIN") // 해당 API는 ADMIN 권한이 필요
                        .anyRequest().authenticated() // 그 외 모든 요청은 인증 필요
                )
                .exceptionHandling(exception -> exception.accessDeniedHandler(new SecurityAccessDeniedHandler(objectMapper)))
                .userDetailsService(userDetailsService)
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider, redis), UsernamePasswordAuthenticationFilter.class) // UsernamePasswordAuthenticationFilter 실행 전에 JwtAuthenticationFilter를 실행
                .build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return webSecurityCustomizer -> webSecurityCustomizer.ignoring() // 시큐리티 기능 비활성화
                .requestMatchers("/favicon.ico")
                .requestMatchers("/error")
                .requestMatchers(toH2Console());
    }

    /**
     * PasswordEncoder : 스프링 시큐리티에서 사용하는 비밀번호 암호화 인터페이스로 구현체를 빈으로 등록하는 과정이 필요하다.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // DelegatingPasswordEncoder : 여러 암호화 알고리즘을 지원
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}
