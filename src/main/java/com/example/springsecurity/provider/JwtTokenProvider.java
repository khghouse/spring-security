package com.example.springsecurity.provider;

import com.example.springsecurity.dto.response.JwtToken;
import com.example.springsecurity.dto.response.SecurityUser;
import com.example.springsecurity.enumeration.JwtErrorCode;
import com.example.springsecurity.exception.BusinessException;
import com.example.springsecurity.exception.JwtException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
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

    @Getter
    @Value("${jwt.expiration-seconds.access-token}")
    private Long accessTokenExpirationSeconds;

    @Getter
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
        // 인증 객체에서 권한 정보를 추출
        String authorities = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        SecurityUser securityUser = SecurityUser.of(authentication);

        // 액세스 토큰 생성
        String accessToken = Jwts.builder()
                .subject(authentication.getName())
                .signWith(accessKey)
                .claim("memberId", securityUser.getMemberId())
                .claim("email", securityUser.getEmail())
                .claim("authorities", authorities)
                .expiration(generateExpiration(accessTokenExpirationSeconds))
                .compact();

        // 리프레쉬 토큰 생성
        String refreshToken = Jwts.builder()
                .signWith(refreshKey)
                .expiration(generateExpiration(refreshTokenExpirationSeconds))
                .compact();

        return JwtToken.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    public Authentication getAuthentications(String accessToken) {
        Claims claims = parseClaims(accessToken, accessKey);

        if (claims.get("authorities") == null) {
            throw new BusinessException("권한 정보가 없는 토큰입니다.");
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
        } catch (MalformedJwtException e) {
            throw new JwtException(JwtErrorCode.MALFORMED);
        } catch (ExpiredJwtException e) {
            throw new JwtException(JwtErrorCode.EXPIRED);
        } catch (UnsupportedJwtException e) {
            throw new JwtException(JwtErrorCode.UNSUPPORTED);
        } catch (Exception e) {
            throw new JwtException(JwtErrorCode.INVALID);
        }

        return true;
    }

    public void validateTokenByRefreshToken(String token) {
        try {
            parseClaims(token, refreshKey);
        } catch (MalformedJwtException e) {
            throw new JwtException(JwtErrorCode.MALFORMED);
        } catch (ExpiredJwtException e) {
            throw new JwtException(JwtErrorCode.EXPIRED);
        } catch (UnsupportedJwtException e) {
            throw new JwtException(JwtErrorCode.UNSUPPORTED);
        } catch (Exception e) {
            throw new JwtException(JwtErrorCode.INVALID);
        }
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
