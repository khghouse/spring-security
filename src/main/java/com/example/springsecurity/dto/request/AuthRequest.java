package com.example.springsecurity.dto.request;

import lombok.*;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class AuthRequest {

    private String email;
    private String password;

    public AuthServiceRequest toServiceRequest() {
        return AuthServiceRequest.builder()
                .email(email)
                .password(password)
                .build();
    }

}
