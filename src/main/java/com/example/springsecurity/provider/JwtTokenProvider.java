package com.example.springsecurity.provider;

import com.example.springsecurity.dto.response.JwtToken;
import com.example.springsecurity.dto.response.SecurityUser;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtTokenProvider {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_TYPE = "Bearer";

    @Value("${jwt.secret.access-token}")
    private String accessTokenSecret;

    @Value("${jwt.secret.refresh-token}")
    private String refreshTokenSecret;

    @Value("${jwt.expiration-seconds.access-token}")
    private Long accessTokenExpirationSeconds;

    @Value("${jwt.expiration-seconds.refresh-token}")
    private Long refreshTokenExpirationSeconds;

    private SecretKey accessKey;
    private SecretKey refreshKey;

    @PostConstruct
    void init() {
        this.accessKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(accessTokenSecret));
        this.refreshKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshTokenSecret));
    }

    /**
     * 토큰을 생성한다.
     */
    public JwtToken generateToken(Authentication authentication) {
        // org.springframework.security.core.userdetails.User의 Set<GrantedAuthority> authorities
        String authorities = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        SecurityUser securityUser = SecurityUser.of(authentication);

        String accessToken = Jwts.builder()
                .subject(authentication.getName())
                .signWith(accessKey)
                .claim("memberId", securityUser.getMemberId())
                .claim("email", securityUser.getEmail())
                .claim("authorities", authorities)
                .expiration(generateExpiration(accessTokenExpirationSeconds))
                .compact();

        String refreshToken = Jwts.builder()
                .signWith(refreshKey)
                .expiration(generateExpiration(refreshTokenExpirationSeconds))
                .compact();

        return JwtToken.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .refreshTokenExpirationSeconds(refreshTokenExpirationSeconds)
                .build();
    }

    public Authentication getAuthentications(String accessToken) {
        Claims claims = parseClaims(accessToken, accessKey);

        if (claims.get("authorities") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        // 클레임에서 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities = Arrays.stream(
                        claims.get("authorities").toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        UserDetails securityUser = new SecurityUser(claims.get("memberId", Long.class), claims.get("email", String.class), authorities);
        return new UsernamePasswordAuthenticationToken(securityUser, null, authorities);
    }

    public Long getMemberIdByAccessToken(String accessToken) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(accessKey)
                    .build()
                    .parseSignedClaims(accessToken)
                    .getPayload();
            return claims.get("memberId", Long.class);
        } catch (ExpiredJwtException e) {
            return e.getClaims().get("memberId", Long.class);
        }
    }

    public boolean validateToken(String token) {
        try {
            parseClaims(token, accessKey);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.info("[Invalid JWT Token] ", e);
        } catch (ExpiredJwtException e) {
            log.info("[Expired JWT Token] ", e);
        } catch (UnsupportedJwtException e) {
            log.info("[Unsupported JWT Token] ", e);
        } catch (IllegalArgumentException e) {
            log.info("[JWT claims string is empty] ", e);
        } catch (Exception e) {
            log.info("[Invalid JWT Token] ", e);
        }

        return false;
    }

    public boolean validateTokenByRefreshToken(String token) {
        try {
            parseClaims(token, refreshKey);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.info("[Invalid JWT Token] ", e);
        } catch (ExpiredJwtException e) {
            log.info("[Expired JWT Token] ", e);
        } catch (UnsupportedJwtException e) {
            log.info("[Unsupported JWT Token] ", e);
        } catch (IllegalArgumentException e) {
            log.info("[JWT claims string is empty] ", e);
        } catch (Exception e) {
            log.info("[Invalid JWT Token] ", e);
        }

        return false;
    }

    /**
     * 해더에서 인증 타입을 제외한 토큰 값만 추출
     */
    public String resolveToken(HttpServletRequest request) {
        String token = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(token) && token.startsWith(BEARER_TYPE)) {
            return token.substring(BEARER_TYPE.length() + 1);
        }
        return null;
    }

    private Claims parseClaims(String token, SecretKey key) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * 토큰 만료 일시를 생성한다.
     */
    private Date generateExpiration(Long millisecond) {
        return new Date(System.currentTimeMillis() + millisecond * 1000L);
    }

}
