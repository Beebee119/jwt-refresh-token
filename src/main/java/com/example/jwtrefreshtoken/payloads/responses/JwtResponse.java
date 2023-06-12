package com.example.jwtrefreshtoken.payloads.responses;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class JwtResponse {
    private String accessToken;

    private String refreshToken;

    private String userStatus;
}
