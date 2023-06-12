package com.boniface.springsecuritypractice.web.rest;

import com.boniface.springsecuritypractice.exception.InvalidEmailException;
import com.boniface.springsecuritypractice.exception.UserAlreadyExistsException;
import com.boniface.springsecuritypractice.service.RegistrationService;
import com.boniface.springsecuritypractice.service.dto.RESTResponse;
import com.boniface.springsecuritypractice.service.dto.RegistrationRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/api/registration")
public class RegistrationController {
    private final RegistrationService registrationService;

    public RegistrationController(RegistrationService registrationService) {
        this.registrationService = registrationService;
    }

    @PostMapping
    public ResponseEntity<RESTResponse> register(@RequestBody RegistrationRequest registrationRequest) throws
            UserAlreadyExistsException, InvalidEmailException {
        registrationService.register(registrationRequest);
        return ResponseEntity.ok().body(new RESTResponse(false, "User registered Successfully!" +
                " Check your email for a confirmation token"));

    }

    @GetMapping(path = "confirm")
    public ResponseEntity<RESTResponse> confirm(@RequestParam("token") String token) {
        String response = registrationService.confirmToken(token);
        return ResponseEntity.ok().body(new RESTResponse(false, response));
    }

    @GetMapping(path = "reset")
    public ResponseEntity<RESTResponse> reset(@RequestParam("msisdn") String msisdn) {
        String response = registrationService.requestOTP(msisdn, "RESET");
        return ResponseEntity.ok().body(new RESTResponse(false, response));
    }

    @GetMapping(path = "resend")
    public ResponseEntity<RESTResponse> resend(@RequestParam("msisdn") String msisdn) {
        String response = registrationService.requestOTP(msisdn, "RESEND");
        return ResponseEntity.ok().body(new RESTResponse(false, response));

    }
}
