package com.boniface.springsecuritypractice.security;

import com.boniface.springsecuritypractice.domain.User;
import com.boniface.springsecuritypractice.domain.enums.UserRole;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

import java.util.Optional;

public class SecurityUtil {
    // get token from context
    public static Optional<String> getCurrentUserJWT() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        return Optional
                .ofNullable(securityContext.getAuthentication())
                .filter(authentication -> authentication.getCredentials() instanceof String)
                .map(authentication -> (String) authentication.getCredentials());
    }


    // get current user
    public static Optional<User> getCurrentUser(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            return Optional.empty();
        } else if (authentication.getPrincipal() instanceof User) {
            return Optional.ofNullable((User) authentication.getPrincipal());
        }

        return Optional.empty();
    }

    // get current user msisdn
    public static String getCurrentUserMsisdn() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        return Optional.ofNullable(extractMsisdnFromPrincipal(securityContext.getAuthentication())).orElse("unknown");
    }

    // get current user email
    public static String getCurrentUserEmail() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        return Optional.ofNullable(extractEmailFromPrincipal(securityContext.getAuthentication())).orElse("unknown");
    }

    // get current userRole
    public static UserRole getCurrentUserRole() {
        SecurityContext securityContext = SecurityContextHolder.getContext();
        return Optional.ofNullable(extractRoleFromPrincipal(securityContext.getAuthentication())).orElse(UserRole.ANONYMOUS);
    }


    // Extracts Email from principle
    private static String extractEmailFromPrincipal(Authentication authentication) {
        if (authentication == null) {
            return null;
        } else if (authentication.getPrincipal() instanceof User) {
            User user = (User) authentication.getPrincipal();
            return user.getEmailAddress();
        }

        return null;
    }

    // extract role from principle
    private static UserRole extractRoleFromPrincipal(Authentication authentication) {
        if (authentication == null) {
            return null;
        } else if (authentication.getPrincipal() instanceof User) {
            User user = (User) authentication.getPrincipal();
            return user.getUserRole();
        }

        return null;
    }


    // Extracts Msisdn from principle
    private static String extractMsisdnFromPrincipal(Authentication authentication) {
        if (authentication == null) {
            return null;
        } else if (authentication.getPrincipal() instanceof User) {
            User user = (User) authentication.getPrincipal();
            return user.getMsisdn();
        }

        return null;
    }

    // logoutUser
    public static boolean logoutUser(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Optional<User> currUser = getCurrentUser();

        if(currUser.isPresent()){
            SecurityContextLogoutHandler ctxLogOut = new SecurityContextLogoutHandler();
            ctxLogOut.logout(request,response,auth);
            return true;
        }

        return false;


    }
}
