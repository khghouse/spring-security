package com.example.springsecurity.component;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
@Transactional
@ActiveProfiles("test")
class RedisTest {

    private final String PREFIX_REDIS_KEY_REFRESH_TOKEN = "refreshToken:";

    @Autowired
    private Redis redis;

    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    @Test
    @DisplayName("레디스에 등록된 key로 조회하면 value를 리턴한다.")
    void get() {
        // given
        redisTemplate.opsForValue()
                .set("key", "value", 3, TimeUnit.SECONDS);

        // when
        String result = redis.get("key");

        // then
        assertThat(result).isEqualTo("value");
    }

    @Test
    @DisplayName("레디스에 존재하지 않는 key로 조회하면 null을 리턴한다.")
    void getInvalidKey() {
        // given
        redisTemplate.opsForValue()
                .set("key", "value", 3, TimeUnit.SECONDS);

        // when
        String result = redis.get("key2");

        // then
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("유효시간이 지난 레디스 key로 조회하면 null을 리턴한다.")
    void getTimeoutKey() throws Exception {
        // given
        redisTemplate.delete("key");
        redisTemplate.opsForValue()
                .set("key", "value", 1, TimeUnit.SECONDS);
        TimeUnit.SECONDS.sleep(1);

        // when
        String result = redis.get("key");

        // then
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("레디스에 리프레쉬 토큰을 등록하고 확인한다.")
    void setRefreshToken() {
        // when
        redis.setRefreshToken(1L, "refreshToken");

        // then
        String result = redisTemplate.opsForValue()
                .get(PREFIX_REDIS_KEY_REFRESH_TOKEN + 1L);

        assertThat(result).isEqualTo("refreshToken");

        // tearDown
        redisTemplate.delete(PREFIX_REDIS_KEY_REFRESH_TOKEN + 1L);
    }

    @Test
    @DisplayName("요청 파라미터로 전달받은 리프레쉬 토큰과 레디스에 저장된 토큰을 비교한다.")
    void compareRefreshToken() {
        // given
        redisTemplate.opsForValue()
                .set(PREFIX_REDIS_KEY_REFRESH_TOKEN + 1L, "refreshToken", 3, TimeUnit.SECONDS);

        String requestRefreshToken = "refreshToken";

        // when
        redis.compareRefreshToken(1L, requestRefreshToken);

        // then
        String result = redisTemplate.opsForValue()
                .get(PREFIX_REDIS_KEY_REFRESH_TOKEN + 1L);
        assertThat(result).isEqualTo("refreshToken");

        // tearDown
        redisTemplate.delete(PREFIX_REDIS_KEY_REFRESH_TOKEN + 1L);
    }

    @Test
    @DisplayName("레디스에 저장된 리프레쉬 토큰과 값은 같지만 회원 ID가 달라 예외가 발생한다.")
    void compareRefreshTokenAnotherMemberId() {
        // given
        redisTemplate.opsForValue()
                .set(PREFIX_REDIS_KEY_REFRESH_TOKEN + 1L, "refreshToken", 3, TimeUnit.SECONDS);

        String requestRefreshToken = "refreshToken";

        // when
        assertThatThrownBy(() -> redis.compareRefreshToken(2L, requestRefreshToken))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("인증 정보가 유효하지 않습니다.");

        // tearDown
        redisTemplate.delete(PREFIX_REDIS_KEY_REFRESH_TOKEN + 1L);
    }

    @Test
    @DisplayName("레디스에 저장된 리프레쉬 토큰의 key는 같지만 value가 달라 예외가 발생한다.")
    void compareRefreshTokenInvalidValue() {
        // given
        redisTemplate.opsForValue()
                .set(PREFIX_REDIS_KEY_REFRESH_TOKEN + 1L, "refreshToken", 3, TimeUnit.SECONDS);

        String requestRefreshToken = "refreshToken2";

        // when
        assertThatThrownBy(() -> redis.compareRefreshToken(1L, requestRefreshToken))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("인증 정보가 유효하지 않습니다.");

        // tearDown
        redisTemplate.delete(PREFIX_REDIS_KEY_REFRESH_TOKEN + 1L);
    }

    @Test
    @DisplayName("레디스에 저장된 리프레쉬 토큰을 삭제하고 확인한다.")
    void deleteRefreshToken() {
        // given
        redisTemplate.opsForValue()
                .set(PREFIX_REDIS_KEY_REFRESH_TOKEN + 1L, "refreshToken", 3, TimeUnit.SECONDS);

        // when
        redis.deleteRefreshToken(1L);

        // then
        String result = redisTemplate.opsForValue()
                .get(PREFIX_REDIS_KEY_REFRESH_TOKEN + 1L);
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("레디스에 저장되었다가 만료된 리프레쉬 토큰을 삭제하고 확인한다.")
    void deleteRefreshTokenExpiration() throws Exception {
        // given
        redisTemplate.delete(PREFIX_REDIS_KEY_REFRESH_TOKEN + 1L);
        redisTemplate.opsForValue()
                .set(PREFIX_REDIS_KEY_REFRESH_TOKEN + 1L, "refreshToken", 1, TimeUnit.SECONDS);
        TimeUnit.SECONDS.sleep(1);

        // when
        redis.deleteRefreshToken(1L);

        // then
        String result = redisTemplate.opsForValue()
                .get(PREFIX_REDIS_KEY_REFRESH_TOKEN + 1L);
        assertThat(result).isNull();
    }

}