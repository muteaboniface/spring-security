package com.boniface.springsecuritypractice.web.rest;

import com.boniface.springsecuritypractice.domain.User;
import com.boniface.springsecuritypractice.security.JWTTokenUtil;
import com.boniface.springsecuritypractice.service.UserService;
import com.boniface.springsecuritypractice.service.dto.Login;
import com.boniface.springsecuritypractice.service.dto.LoginResponse;
import com.boniface.springsecuritypractice.service.dto.UserDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/token")
public class AuthenticationController {
    private final Logger log = LoggerFactory.getLogger(AuthenticationController.class);
    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JWTTokenUtil jwtTokenUtil;

    public AuthenticationController(UserService userService,
                                  AuthenticationManager authenticationManager,
                                  JWTTokenUtil jwtTokenUtil) {
        this.userService = userService;
        this.authenticationManager = authenticationManager;
        this.jwtTokenUtil = jwtTokenUtil;
    }

    @PostMapping
    public ResponseEntity<LoginResponse> generateToken(@RequestBody Login login) {
        log.info("Login Request");
        User user = userService.findByUsername(login.getUsername());

        final Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(login.getUsername(), login.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token = jwtTokenUtil.generateToken(user);
        UserDTO userDto = userService.findByUsernameDto(user.getId());
        LoginResponse loginResponse = new LoginResponse(userDto, token);
        return ResponseEntity.ok().body(loginResponse);

    }
}
