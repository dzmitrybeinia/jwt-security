package com.dzmitrybeinia.webfluxsecurity.rest;

import com.dzmitrybeinia.webfluxsecurity.dto.AuthRequestDto;
import com.dzmitrybeinia.webfluxsecurity.dto.AuthResponseDto;
import com.dzmitrybeinia.webfluxsecurity.dto.UserDto;
import com.dzmitrybeinia.webfluxsecurity.entity.User;
import com.dzmitrybeinia.webfluxsecurity.mapper.UserMapper;
import com.dzmitrybeinia.webfluxsecurity.security.CustomPrincipal;
import com.dzmitrybeinia.webfluxsecurity.security.SecurityService;
import com.dzmitrybeinia.webfluxsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/v1/auth")
public class AuthController {
    private final SecurityService securityService;
    private final UserService userService;
    private final UserMapper userMapper;

    @PostMapping("/register")
    public Mono<UserDto> register(@RequestBody UserDto dto) {
        User user = userMapper.map(dto);
        return userService.registerUser(user)
                .map(userMapper::map);
    }

    @PostMapping("/login")
    public Mono<AuthResponseDto> login(@RequestBody AuthRequestDto authRequestDto) {
        return securityService.authenticate(authRequestDto.getUsername(), authRequestDto.getPassword())
                .flatMap(tokenDetails -> Mono.just(
                        AuthResponseDto.builder()
                                .userId(tokenDetails.getUserId())
                                .token(tokenDetails.getToken())
                                .createdAt(tokenDetails.getCreatedAt())
                                .expiredAt(tokenDetails.getExpiredAt())
                                .build()
                ));
    }

    @GetMapping("/info")
    public Mono<UserDto> getUserInfo(Authentication authentication) {
        CustomPrincipal customPrincipal = (CustomPrincipal) authentication.getPrincipal();
        return userService.getUserById(customPrincipal.getId())
                .map(userMapper::map);
    }
}
