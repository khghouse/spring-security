package com.example.springsecurity.api;

import com.example.springsecurity.dto.request.AuthRequest;
import com.example.springsecurity.dto.request.ReissueRequest;
import com.example.springsecurity.dto.response.ApiResponse;
import com.example.springsecurity.exception.UnauthorizedException;
import com.example.springsecurity.provider.JwtTokenProvider;
import com.example.springsecurity.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final JwtTokenProvider jwtTokenProvider;

    @PostMapping("/signup")
    public ResponseEntity signup(@RequestBody @Validated AuthRequest request) {
        authService.signup(request.toServiceRequest());
        return ResponseEntity.ok(null);
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody @Validated AuthRequest request) {
        return ResponseEntity.ok(authService.login(request.toServiceRequest()));
    }

    @PostMapping("/token/reissue")
    public ResponseEntity reissueToken(@RequestBody @Validated ReissueRequest request) {
        return ResponseEntity.ok(authService.reissueToken(request.toServiceRequest()));
    }

    @PostMapping("/logout")
    public ApiResponse logout(HttpServletRequest request) {
        String accessToken = jwtTokenProvider.resolveToken(request);
        if (accessToken == null) {
            throw new UnauthorizedException("인증되지 않은 요청입니다.");
        }
        authService.logout(accessToken);
        return ApiResponse.ok();
    }

}
