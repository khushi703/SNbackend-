package org.example.service;

import org.example.entities.User;
import org.example.repository.UserRepository;
import org.example.utils.JwtUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final EmailService emailService;
    private final UserRepository userRepository;

    public AuthService(AuthenticationManager authenticationManager,
                       JwtUtil jwtUtil,
                       UserDetailsService userDetailsService,
                       EmailService emailService,
                       UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
        this.emailService = emailService;
        this.userRepository = userRepository;
    }

    public String login(String usernameOrEmail, String password) {
        try {
            // Authenticate using either username or email
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(usernameOrEmail, password)
            );

            // Load user details (works with both username and email)
            UserDetails userDetails = userDetailsService.loadUserByUsername(usernameOrEmail);

            // Generate token using email as subject
            String token = jwtUtil.generateToken(userDetails.getUsername());

            // Find user to get email (handles both username and email lookup)
            User user = userRepository.findFirstByUsernameOrEmail(usernameOrEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with username or email: " + usernameOrEmail));


            // Send login notification if email exists
            if (user.getEmail() != null && !user.getEmail().isEmpty()) {
                emailService.sendLoginNotification(user.getEmail());
            }

            return token;

        } catch (BadCredentialsException e) {
            throw new RuntimeException("Invalid credentials", e);
        }
    }

//    public String generateTokenForOAuth2User(String email) {
//        // Load user details by email
//        UserDetails userDetails = userDetailsService.loadUserByUsername(email);
//
//        // Generate token using email as subject
//        return jwtUtil.generateToken(userDetails.getUsername());
//    }
}