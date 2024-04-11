package com.example.springsecurity.test;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Transactional
@ActiveProfiles("test")
public class RedisTest {

    @Autowired
    private RedisTemplate redisTemplate;

    @Test
    @DisplayName("레디스 서버가 실행된 상태에서 key-value를 등록하고 확인한다.")
    void redisSet() {
        // given
        ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();
        valueOperations.set("redis", "test");

        // when
        String result = valueOperations.get("redis");

        // then
        assertThat(result).isEqualTo("test");
    }

}
