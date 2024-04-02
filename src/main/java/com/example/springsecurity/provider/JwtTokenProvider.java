package com.example.springsecurity.provider;

import com.example.springsecurity.dto.response.JwtToken;
import com.example.springsecurity.dto.response.SecurityUser;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class JwtTokenProvider {

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
                .expiration(getExpiration(accessTokenExpirationSeconds))
                .compact();

        String refreshToken = Jwts.builder()
                .signWith(refreshKey)
                .expiration(getExpiration(refreshTokenExpirationSeconds))
                .compact();

        return JwtToken.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public Authentication getAuthentications(String accessToken) {
        Claims claims = parseClaims(accessToken);

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

    private Claims parseClaims(String accessToken) {
        return Jwts.parser()
                .verifyWith(accessKey)
                .build()
                .parseSignedClaims(accessToken)
                .getPayload();
    }

    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            throw new RuntimeException("Invalid JWT Token", e);
        } catch (ExpiredJwtException e) {
            throw new RuntimeException("Expired JWT Token", e);
        } catch (UnsupportedJwtException e) {
            throw new RuntimeException("Unsupported JWT Token", e);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("JWT claims string is empty", e);
        }
    }

    private Date getExpiration(Long millisecond) {
        return new Date(System.currentTimeMillis() + millisecond * 1000L);
    }

}
