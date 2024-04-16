package com.example.springsecurity.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class AuthRequest {

    @NotBlank(message = "이메일을 입력해 주세요.")
    private String email;

    @NotBlank(message = "비밀번호를 입력해 주세요.")
    private String password;

    public AuthServiceRequest toServiceRequest() {
        return AuthServiceRequest.builder()
                .email(email)
                .password(password)
                .build();
    }

}
