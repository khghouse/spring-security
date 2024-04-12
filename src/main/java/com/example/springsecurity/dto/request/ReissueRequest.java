package com.example.springsecurity.dto.request;

import lombok.*;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ReissueRequest {

    private String accessToken;
    private String refreshToken;

    public ReissueServiceRequest toServiceRequest() {
        return ReissueServiceRequest.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

}
