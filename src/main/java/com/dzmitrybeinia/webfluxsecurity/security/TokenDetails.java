package com.dzmitrybeinia.webfluxsecurity.security;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
public class TokenDetails {
    private Long userId;
    private String token;
    private Date createdAt;
    private Date expiredAt;
}
