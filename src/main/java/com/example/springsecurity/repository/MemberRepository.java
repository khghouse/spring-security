package com.example.springsecurity.repository;

import com.example.springsecurity.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByIdAndDeletedFalse(Long id);

    Optional<Member> findByEmail(String email);

    Optional<Member> findByEmailAndDeletedFalse(String email);

}
