package com.boniface.springsecuritypractice.service;

import com.boniface.springsecuritypractice.domain.ConfirmationToken;
import com.boniface.springsecuritypractice.repository.ConfirmationTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class ConfirmationTokenService {

    private final Logger log = LoggerFactory.getLogger(ConfirmationTokenService.class);
    private final ConfirmationTokenRepository confirmationTokenRepository;

    public ConfirmationTokenService(ConfirmationTokenRepository confirmationTokenRepository) {
        this.confirmationTokenRepository = confirmationTokenRepository;
    }

    public void saveConfirmationToken(ConfirmationToken confirmationToken) {
        confirmationTokenRepository.save(confirmationToken);
    }


    public Optional<ConfirmationToken> getToken(String token) {
        return confirmationTokenRepository.findByToken(token);
    }


    public void setConfirmedAt(String token) {
        ConfirmationToken confirmedUser = confirmationTokenRepository.findByToken(token).orElseThrow(() ->
                new IllegalStateException("Specified Token Not Found!"));

        confirmedUser.setConfirmedAt(LocalDateTime.now());
        confirmedUser.setExpiresAt(LocalDateTime.now()); // Expire token

    }

    public void deleteByUserId(Long id) {
        // drops all entries associated with user
        confirmationTokenRepository.deleteByUserId(id);
        log.info("Confirmation token dropped successfully");
    }
}
