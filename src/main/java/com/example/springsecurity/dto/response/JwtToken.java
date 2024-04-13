package com.example.springsecurity.dto.response;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class JwtToken {

    private final String accessToken;
    private final String refreshToken;

    @JsonIgnore
    private final Long refreshTokenExpirationSeconds;

}
