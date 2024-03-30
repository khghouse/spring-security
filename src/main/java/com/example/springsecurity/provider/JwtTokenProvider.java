package com.example.springsecurity.provider;

import com.example.springsecurity.dto.response.SecurityUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
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

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.accessToken-expiration-millisecond}")
    private Long accessTokenExpirationMillisecond;

    private SecretKey key;

    @PostConstruct
    void init() {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    public String generateAccessToken(Authentication authentication) {
        // org.springframework.security.core.userdetails.User의 Set<GrantedAuthority> authorities
        String authorities = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        SecurityUser securityUser = SecurityUser.of(authentication);

        return Jwts.builder()
                .subject(authentication.getName())
                .signWith(key, SignatureAlgorithm.HS256)
                .claim("memberId", securityUser.getMemberId())
                .claim("email", securityUser.getEmail())
                .claim("authorities", authorities)
                .expiration(getExpiration(accessTokenExpirationMillisecond))
                .compact();
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

        UserDetails securityUser = new SecurityUser((Long) claims.get("memberId"), (String) claims.get("email"), authorities);
        return new UsernamePasswordAuthenticationToken(securityUser, null, authorities);
    }

    private Claims parseClaims(String accessToken) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(accessToken)
                .getPayload();
    }

    private Date getExpiration(Long millisecond) {
        return new Date(System.currentTimeMillis() + millisecond * 1000L);
    }

}
