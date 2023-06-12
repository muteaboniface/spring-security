package com.boniface.springsecuritypractice.service;

import com.boniface.springsecuritypractice.domain.ConfirmationToken;
import com.boniface.springsecuritypractice.domain.User;
import com.boniface.springsecuritypractice.domain.enums.UserRole;
import com.boniface.springsecuritypractice.exception.InvalidEmailException;
import com.boniface.springsecuritypractice.exception.UserAlreadyExistsException;
import com.boniface.springsecuritypractice.service.dto.RegistrationRequest;
import com.boniface.springsecuritypractice.service.util.EmailValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
public class RegistrationService {

    private final Logger log = LoggerFactory.getLogger(RegistrationService.class);

    private final static String EMAIL_NOT_VALID = "EMAIL %s IS NOT VALID";
    private final static String PHONE_NOT_VALID = "PHONE %s IS NOT VALID";
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;
    private final ConfirmationTokenService confirmationTokenService;


    public RegistrationService(PasswordEncoder passwordEncoder, UserService userService
            , ConfirmationTokenService confirmationTokenService) {
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
        this.confirmationTokenService = confirmationTokenService;
    }

    // Register User
    public void register(RegistrationRequest registrationRequest) throws
            InvalidEmailException, UserAlreadyExistsException {

        log.info("Registering New User");
        EmailValidator emailValidator = new EmailValidator();
        boolean isValidEmail = emailValidator.test(registrationRequest.getEmail());

        if(!isValidEmail){
            throw new InvalidEmailException(String.format(EMAIL_NOT_VALID,registrationRequest.getEmail()));
        }

        if(userService.doesUserExist(registrationRequest.getMsisdn(),registrationRequest.getEmail())){
            throw new UserAlreadyExistsException("User Already Exists");
        }

        User user = new User();
        user.setFirstName(registrationRequest.getFirstName());
        user.setLastName((registrationRequest.getLastName()));
        user.setMsisdn(registrationRequest.getMsisdn());
        user.setEmailAddress(registrationRequest.getEmail());
        user.setPassword(registrationRequest.getPassword());
        user.setUsername(registrationRequest.getMsisdn());
        user.setCreatedBy(registrationRequest.getMsisdn());

        // signup user
        List<Object> response =  userService.signUpUser(user, UserRole.ADMIN);

        User registeredUser = (User) response.get(0);
        String token = (String) response.get(1);

        // send confirmation token
    }


    // Confirm token
    @Transactional
    public String confirmToken(String token) {
        ConfirmationToken confirmationToken = confirmationTokenService.getToken(token).orElseThrow(() ->
                new IllegalStateException("INVALID OTP!"));

        if (confirmationToken.getConfirmedAt() != null) {
            throw new IllegalStateException("Phone Number Already Confirmed!");

        }

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();

        if (expiredAt.isBefore(LocalDateTime.now())) {
            throw new IllegalStateException("Token Expired!");

        }

        confirmationTokenService.setConfirmedAt(token);

        userService.enableAppUser(confirmationToken.getUser().getMsisdn());

        return "Account Confirmed, You can Proceed to Login";

    }

    // Request OTP
    public String requestOTP(String msisdn, String action) {

        log.info("Generating OTP");

        User user = userService.findByMsisdn(msisdn);

        // Generate a Random 6 digit OTP - 0 - 999999
        int randomOTP = (int) ((Math.random() * (999999 - 1)) + 1);
        String token = String.format("%06d", randomOTP);

        ConfirmationToken confirmationToken = new ConfirmationToken(
                token,
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(3), // Expires after 3 minutes
                user
        );
        confirmationTokenService.saveConfirmationToken(confirmationToken);
        log.info("Reset OTP generated : {}",token);

        // Sending Confirmation OTP

        return "OTP SENT TO " + msisdn;
    }

}
