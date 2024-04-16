package com.example.springsecurity.api;

import com.example.springsecurity.dto.request.AuthRequest;
import com.example.springsecurity.dto.request.ReissueRequest;
import com.example.springsecurity.provider.JwtTokenProvider;
import com.example.springsecurity.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = AuthController.class)
@WithMockUser
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuthService authService;

    @MockBean
    private JwtTokenProvider jwtTokenProvider;

    @Test
    @DisplayName("회원가입 후 정상 응답한다.")
    void signup() throws Exception {
        // given
        AuthRequest request = AuthRequest.builder()
                .email("khghouse@daum.net")
                .password("password12#$")
                .build();

        // when, then
        mockMvc.perform(post("/auth/signup")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("회원가입 시 이메일은 필수입니다.")
    void signupWithoutEmail() throws Exception {
        // given
        AuthRequest request = AuthRequest.builder()
                .password("password12#$")
                .build();

        // when, then
        mockMvc.perform(post("/auth/signup")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.data").isEmpty())
                .andExpect(jsonPath("$.error").value("이메일을 입력해 주세요."));
    }

    @Test
    @DisplayName("회원가입 시 이메일이 공백이면 클라이언트 에러를 응답한다.")
    void signupBlankEmail() throws Exception {
        // given
        AuthRequest request = AuthRequest.builder()
                .email("     ")
                .password("password12#$")
                .build();

        // when, then
        mockMvc.perform(post("/auth/signup")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.data").isEmpty())
                .andExpect(jsonPath("$.error").value("이메일을 입력해 주세요."));
    }

    @Test
    @DisplayName("회원가입 시 비밀번호는 필수입니다.")
    void signupWithoutPassword() throws Exception {
        // given
        AuthRequest request = AuthRequest.builder()
                .email("khghouse@daum.net")
                .build();

        // when, then
        mockMvc.perform(post("/auth/signup")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.data").isEmpty())
                .andExpect(jsonPath("$.error").value("비밀번호를 입력해 주세요."));
    }

    @Test
    @DisplayName("회원가입 시 비밀번호가 공백이면 클라이언트 에러를 응답한다.")
    void signupBlankPassword() throws Exception {
        // given
        AuthRequest request = AuthRequest.builder()
                .email("khghouse@daum.net")
                .password("     ")
                .build();

        // when, then
        mockMvc.perform(post("/auth/signup")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.data").isEmpty())
                .andExpect(jsonPath("$.error").value("비밀번호를 입력해 주세요."));
    }

    @Test
    @DisplayName("로그인 후 정상 응답한다.")
    void login() throws Exception {
        // given
        AuthRequest request = AuthRequest.builder()
                .email("khghouse@daum.net")
                .password("password12#$")
                .build();

        // when, then
        mockMvc.perform(post("/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("로그인 시 이메일은 필수입니다.")
    void loginWithoutEmail() throws Exception {
        // given
        AuthRequest request = AuthRequest.builder()
                .password("password12#$")
                .build();

        // when, then
        mockMvc.perform(post("/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.data").isEmpty())
                .andExpect(jsonPath("$.error").value("이메일을 입력해 주세요."));
    }

    @Test
    @DisplayName("로그인 시 이메일이 공백이면 클라이언트 에러를 응답한다.")
    void loginBlankEmail() throws Exception {
        // given
        AuthRequest request = AuthRequest.builder()
                .email("     ")
                .password("password12#$")
                .build();

        // when, then
        mockMvc.perform(post("/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.data").isEmpty())
                .andExpect(jsonPath("$.error").value("이메일을 입력해 주세요."));
    }

    @Test
    @DisplayName("로그인 시 비밀번호는 필수입니다.")
    void loginWithoutPassword() throws Exception {
        // given
        AuthRequest request = AuthRequest.builder()
                .email("khghouse@daum.net")
                .build();

        // when, then
        mockMvc.perform(post("/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.data").isEmpty())
                .andExpect(jsonPath("$.error").value("비밀번호를 입력해 주세요."));
    }

    @Test
    @DisplayName("로그인 시 비밀번호가 공백이면 클라이언트 에러를 응답한다.")
    void loginBlankPassword() throws Exception {
        // given
        AuthRequest request = AuthRequest.builder()
                .email("khghouse@daum.net")
                .password("     ")
                .build();

        // when, then
        mockMvc.perform(post("/auth/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.data").isEmpty())
                .andExpect(jsonPath("$.error").value("비밀번호를 입력해 주세요."));
    }

    @Test
    @DisplayName("토큰 재발행 API 호출 후 정상 응답한다.")
    void reissueToken() throws Exception {
        // given
        ReissueRequest request = ReissueRequest.builder()
                .accessToken("json.web.accessToken")
                .refreshToken("json.web.refreshToken")
                .build();

        // when, then
        mockMvc.perform(post("/auth/token/reissue")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("토큰 재발행 시 액세스 토큰은 필수입니다.")
    void reissueTokenWithoutEmail() throws Exception {
        // given
        ReissueRequest request = ReissueRequest.builder()
                .refreshToken("json.web.refreshToken")
                .build();

        // when, then
        mockMvc.perform(post("/auth/token/reissue")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.data").isEmpty())
                .andExpect(jsonPath("$.error").value("액세스 토큰을 입력해 주세요."));
    }

    @Test
    @DisplayName("토큰 재발행 시 액세스 토큰이 공백이면 클라이언트 에러를 응답한다.")
    void reissueTokenBlankEmail() throws Exception {
        // given
        ReissueRequest request = ReissueRequest.builder()
                .accessToken("     ")
                .refreshToken("json.web.refreshToken")
                .build();

        // when, then
        mockMvc.perform(post("/auth/token/reissue")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.data").isEmpty())
                .andExpect(jsonPath("$.error").value("액세스 토큰을 입력해 주세요."));
    }

    @Test
    @DisplayName("토큰 재발행 시 리프레쉬 토큰은 필수입니다.")
    void reissueTokenWithoutPassword() throws Exception {
        // given
        ReissueRequest request = ReissueRequest.builder()
                .accessToken("json.web.accessToken")
                .build();

        // when, then
        mockMvc.perform(post("/auth/token/reissue")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.data").isEmpty())
                .andExpect(jsonPath("$.error").value("리프레쉬 토큰을 입력해 주세요."));
    }

    @Test
    @DisplayName("토큰 재발행 시 리프레쉬 토큰이 공백이면 클라이언트 에러를 응답한다.")
    void reissueTokenBlankPassword() throws Exception {
        // given
        ReissueRequest request = ReissueRequest.builder()
                .accessToken("json.web.accessToken")
                .refreshToken("     ")
                .build();

        // when, then
        mockMvc.perform(post("/auth/token/reissue")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.data").isEmpty())
                .andExpect(jsonPath("$.error").value("리프레쉬 토큰을 입력해 주세요."));
    }

    @Test
    @DisplayName("로그아웃 후 정상 응답한다.")
    void logout() throws Exception {
        // given
        String accessToken = "json.web.token";

        BDDMockito.given(jwtTokenProvider.resolveToken(any()))
                .willReturn("json.web.token");

        // when, then
        mockMvc.perform(post("/auth/logout")
                        .with(csrf())
                        .header("Authorization", "Bearer " + accessToken))
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("로그아웃 시 액세스 토큰이 없다면 예외가 발생한다.")
    void logoutWithoutAccessToken() throws Exception {
        // when, then
        mockMvc.perform(post("/auth/logout")
                        .with(csrf()))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value("400"))
                .andExpect(jsonPath("$.data").isEmpty())
                .andExpect(jsonPath("$.error").value("액세스 토큰을 입력해 주세요."));
    }

}