package com.dzmitrybeinia.webfluxsecurity.security;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.Principal;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class CustomPrincipal implements Principal {
    private Long id;
    private String name;
}
