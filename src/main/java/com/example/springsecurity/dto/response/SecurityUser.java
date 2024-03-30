package com.example.springsecurity.dto.response;

import com.example.springsecurity.entity.Member;
import lombok.Getter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.List;

@Getter
public class SecurityUser extends User {

    private final Long memberId;
    private final String email;

    public SecurityUser(Member member) {
        super(member.getEmail(), "", List.of(new SimpleGrantedAuthority("ROLE_USER")));
        this.memberId = member.getId();
        this.email = member.getEmail();
    }

    public SecurityUser(Long memberId, String email, Collection<? extends GrantedAuthority> authorities) {
        super(email, "", authorities);
        this.memberId = memberId;
        this.email = email;
    }

    public static SecurityUser of(Authentication authentication) {
        validateAuthentication(authentication);
        return (SecurityUser) authentication.getPrincipal();
    }

    private static void validateAuthentication(Authentication authentication) {
        if (authentication == null || authentication.getPrincipal() == null) {
            throw new IllegalArgumentException("인증이 유효하지 않습니다.");
        }

        if (!(authentication.getPrincipal() instanceof SecurityUser)) {
            throw new IllegalArgumentException("인증 객체가 유효하지 않습니다.");
        }
    }

}
