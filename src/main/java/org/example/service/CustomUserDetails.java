package org.example.service;

import org.example.entities.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

public class CustomUserDetails implements UserDetails {

    private static final Logger logger = LoggerFactory.getLogger(CustomUserDetails.class);

    private final User user;

    public CustomUserDetails(User user) {
        this.user = user;
        logger.debug("Initializing CustomUserDetails for user: {}", user.getEmail());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        logger.debug("Fetching authorities for user: {}", user.getEmail());
        // Return the user's roles/authorities if applicable
        return Collections.emptyList(); // Replace with actual roles if applicable
    }

    @Override
    public String getPassword() {
        logger.debug("Returning password for user: {}", user.getEmail());
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        logger.debug("Returning username for user: {}", user.getUsername());
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        logger.debug("Checking if account is non-expired for user: {}", user.getEmail());
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        logger.debug("Checking if account is non-locked for user: {}", user.getEmail());
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        logger.debug("Checking if credentials are non-expired for user: {}", user.getEmail());
        return true;
    }

    @Override
    public boolean isEnabled() {
        logger.debug("Checking if user is enabled: {}", user.getEmail());
        return true;
    }

    public User getUser() {
        logger.debug("Returning user entity for: {}", user.getEmail());
        return user;
    }
}
