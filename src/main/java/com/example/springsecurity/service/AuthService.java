package com.example.springsecurity.service;

import com.example.springsecurity.dto.request.AuthServiceRequest;
import com.example.springsecurity.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final MemberRepository memberRepository;

    public void signup(AuthServiceRequest request) {

    }

    public void login(AuthServiceRequest request) {

    }

}
