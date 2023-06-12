package com.boniface.springsecuritypractice.repository;

import com.boniface.springsecuritypractice.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByMsisdn(String msisdn);

    Optional<User> findByEmailAddress(String username);

    User findUserById(Long userId);

}
