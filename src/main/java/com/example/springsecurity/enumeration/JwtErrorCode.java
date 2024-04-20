package com.example.springsecurity.enumeration;

import lombok.Getter;

@Getter
public enum JwtErrorCode {

    MALFORMED("손상된 토큰입니다."),
    UNSUPPORTED("지원하지 않는 토큰입니다."),
    EXPIRED("만료된 토큰입니다."),
    INVALID("유효하지 않는 토큰입니다."),
    UNAUTHORIZED("인증되지 않은 요청입니다.");

    private final String message;

    JwtErrorCode(String message) {
        this.message = message;
    }

}
