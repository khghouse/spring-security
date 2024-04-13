package com.example.springsecurity.test;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Transactional
@ActiveProfiles("test")
public class RedisTest {

    @Autowired
    private RedisTemplate redisTemplate;

    @Test
    @DisplayName("레디스에서 key-value를 등록하고 확인한다.")
    void redisSet() {
        // given
        ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();
        valueOperations.set("redis", "test");

        // when
        String result = valueOperations.getAndDelete("redis");

        // then
        assertThat(result).isEqualTo("test");
    }

    @Test
    @DisplayName("레디스에서 2초 동안 유효한 key-value를 등록하고, 만료 전 확인한다.")
    void redisSetAndTime() throws Exception {
        // given
        ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();
        valueOperations.set("redis", "test", 2, TimeUnit.SECONDS);
        TimeUnit.SECONDS.sleep(1);

        // when
        String result = valueOperations.get("redis");

        // then
        assertThat(result).isEqualTo("test");
    }

    @Test
    @DisplayName("레디스에서 2초 동안 유효한 key-value를 등록하고, 만료 후 확인한다.")
    void redisExpiration() throws Exception {
        // given
        ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();
        valueOperations.set("redis", "test", 2, TimeUnit.SECONDS);
        TimeUnit.SECONDS.sleep(2);

        // when
        String result = valueOperations.get("redis");

        // then
        assertThat(result).isNull();
    }

}
