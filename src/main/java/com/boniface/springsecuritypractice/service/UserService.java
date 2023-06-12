package com.boniface.springsecuritypractice.service;

import com.boniface.springsecuritypractice.domain.ConfirmationToken;
import com.boniface.springsecuritypractice.domain.User;
import com.boniface.springsecuritypractice.domain.enums.UserRole;
import com.boniface.springsecuritypractice.domain.enums.UserStatus;
import com.boniface.springsecuritypractice.exception.UserAlreadyExistsException;
import com.boniface.springsecuritypractice.repository.UserRepository;
import com.boniface.springsecuritypractice.service.dto.UserDTO;
import com.boniface.springsecuritypractice.service.mapper.UserMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
public class UserService implements UserDetailsService {

    private final Logger log = LoggerFactory.getLogger(UserService.class);
    private final static String USER_NOT_FOUND_MSG = "user %s not found!";
    private final static String USER_EXISTS = "User %s Taken!";
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final ConfirmationTokenService confirmationTokenService;
    private final UserMapper userMapper;

    public UserService(PasswordEncoder passwordEncoder,UserRepository userRepository,
                       ConfirmationTokenService confirmationTokenService, UserMapper userMapper) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.confirmationTokenService = confirmationTokenService;
        this.userMapper = userMapper;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        if (username.contains("@")) {
            return userRepository.findByEmailAddress(username)
                    .orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, username)));
        }
        return findByMsisdn(username);
    }

    public User findByUsername(String username) {
        if (username.contains("@")) {
            return findByEmailAddress(username);
        }
        return findByMsisdn(username);
    }

    public User findByMsisdn(String msisdn) {
        log.info("Request to find user with phone : {}", msisdn);
        return userRepository.findByMsisdn(msisdn)
                .orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, msisdn)));
    }

    public User findByEmailAddress(String email) {
        log.info("Request to find user with email : {}", email);
        return userRepository.findByEmailAddress(email)
                .orElseThrow(()
                        -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, email)));
    }


    // DTO object to return on login
    public UserDTO findByUsernameDto(Long userId) {
        return userMapper.toDto(userRepository.findUserById(userId));
    }

    // EnableUser
    public void enableAppUser(String msisdn) {
        User user = userRepository.findByMsisdn(msisdn)
                .orElseThrow(() -> new UsernameNotFoundException(String.format(USER_NOT_FOUND_MSG, msisdn)));

        user.setEnabled(true); // class is transactional
        user.setUserStatus(UserStatus.ACTIVE);
    }

    public boolean doesUserExist(String msisdn, String email) {
        boolean userExists = userRepository.findByMsisdn(msisdn)
                .isPresent();

        if (userExists) {
            return true;
        }

        return userRepository.findByEmailAddress(email)
                .isPresent();

    }

    public List<Object> signUpUser(User user, UserRole userRole) throws UserAlreadyExistsException {

        log.info("Signing up {}", userRole.name());
        if (userRole != UserRole.ADMIN) { // Admin validation Already done
            boolean userExists = userRepository.findByMsisdn(user.getMsisdn())
                    .isPresent();

            if (userExists) {
                throw new UserAlreadyExistsException(String.format(USER_EXISTS, user.getMsisdn()));
            }
            boolean emailTaken = userRepository.findByEmailAddress(user.getEmailAddress())
                    .isPresent();

            if (emailTaken) {
                throw new UserAlreadyExistsException(String.format(USER_EXISTS, user.getEmailAddress()));
            }
        }

        // Add user
        if (userRole == UserRole.ADMIN) {
            String encodedPassword = passwordEncoder.encode(user.getPassword());

            // Set details
            user.setPassword(encodedPassword);
            user.setUserRole(userRole);
        }

        user.setUserStatus(UserStatus.INACTIVE);

        // save the User in the database
        User user1 = userRepository.save(user);
        log.info("{} saved", userRole.name());


        // Generate a Random 6 digit OTP - 0 - 999999
        int randomOTP = (int) ((Math.random() * (999999 - 1)) + 1);
        String token = String.format("%06d", randomOTP);

        ConfirmationToken confirmationToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(24 * 60 * 3), // 3 DAYS Expiry
                user
        );

        confirmationTokenService.saveConfirmationToken(confirmationToken);
        log.info("Confirmation token generated: {}",token);

        List<Object> response = new ArrayList<>();
        response.add(user1);
        response.add(token);

        return response;

    }

    public void saveUser(User user) {
        userRepository.save(user);
    }
}
