package com.boniface.springsecuritypractice.domain;


import com.boniface.springsecuritypractice.config.AbstractAuditingEntity;
import com.boniface.springsecuritypractice.domain.enums.UserRole;
import com.boniface.springsecuritypractice.domain.enums.UserStatus;
import jakarta.persistence.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;
import java.util.Collections;

@Entity
@Table(name = "tbl_users")
public class User extends AbstractAuditingEntity<Long> implements UserDetails {

    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Id
    private Long id;

    @Column(name = "first_name", length = 16)
    private String firstName;

    @Column(name = "last_name", length = 16)
    private String lastName;

    @Column(name = "msisdn", unique = true, length = 32)
    private String msisdn;

    @Column(name = "email_address", unique = true, length = 32)
    private String emailAddress;

    @Column(name = "user_name", length = 16)
    private String username;

    @Column(name = "password")
    private String password;

    @Column(name = "user_status", length = 16)
    @Enumerated(EnumType.STRING)
    private UserStatus userStatus;

    @Column(name = "user_role", length = 16)
    @Enumerated(EnumType.STRING)
    private UserRole userRole;

    // spring user
    private boolean locked = false;
    private boolean enabled = false;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        SimpleGrantedAuthority grantedAuthority = new SimpleGrantedAuthority(userRole.name());

        return Collections.singletonList(grantedAuthority);
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return msisdn;
    }

    @Override
    public boolean isAccountNonExpired() {
        // allow you to manage and track account expiry
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !locked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public User() {
    }

    @Override
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getMsisdn() {
        return msisdn;
    }

    public void setMsisdn(String msisdn) {
        this.msisdn = msisdn;
    }

    public String getEmailAddress() {
        return emailAddress;
    }

    public void setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public UserStatus getUserStatus() {
        return userStatus;
    }

    public void setUserStatus(UserStatus userStatus) {
        this.userStatus = userStatus;
    }

    public UserRole getUserRole() {
        return userRole;
    }

    public void setUserRole(UserRole userRole) {
        this.userRole = userRole;
    }

    public boolean isLocked() {
        return locked;
    }

    public void setLocked(boolean locked) {
        this.locked = locked;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
