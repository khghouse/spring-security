package com.example.springsecurity.dto.request;

import com.example.springsecurity.entity.Member;
import lombok.*;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class AuthServiceRequest {

    private String email;
    private String password;

    public Member toEntity(String password) {
        return Member.builder()
                .email(email)
                .password(password)
                .deleted(false)
                .build();
    }

}
