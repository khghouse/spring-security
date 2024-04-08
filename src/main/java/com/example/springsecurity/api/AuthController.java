package com.example.springsecurity.api;

import com.example.springsecurity.dto.request.AuthRequest;
import com.example.springsecurity.provider.JwtTokenProvider;
import com.example.springsecurity.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
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
    public ResponseEntity signup(@RequestBody AuthRequest request) {
        authService.signup(request.toServiceRequest());
        return ResponseEntity.ok(null);
    }

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody AuthRequest request) {
        return ResponseEntity.ok(authService.login(request.toServiceRequest()));
    }

    @PostMapping("/token/reissue")
    public ResponseEntity reissueToken(HttpServletRequest request) {
        String refreshToken = jwtTokenProvider.resolveToken(request);
        return ResponseEntity.ok(authService.reissueToken(refreshToken));
    }

}
