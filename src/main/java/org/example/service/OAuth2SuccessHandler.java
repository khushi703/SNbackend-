package org.example.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.entities.User;
import org.example.repository.UserRepository;
import org.example.utils.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

@Component
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private static final Logger log = LoggerFactory.getLogger(OAuth2SuccessHandler.class);

    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final EmailService emailService;

    public OAuth2SuccessHandler(UserRepository userRepository, JwtUtil jwtUtil, EmailService emailService) {
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
        this.emailService = emailService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        log.info("=== OAuth2 SUCCESS HANDLER TRIGGERED ===");

        // Get OAuth2User from authentication object
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

        // Print all attributes for debugging
        oAuth2User.getAttributes().forEach((k, v) -> log.info("Attribute: {} -> {}", k, v));

        // Extract email and name from OAuth2User
        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        if (email == null) {
            log.error("OAuth2 login did not return an email address!");
            response.sendRedirect("http://localhost:5173/error");
            return;
        }

        log.info("Processing OAuth login for email: {}", email);

        // Check if the user already exists, if not create one
        Optional<User> existingUserOpt = userRepository.findByEmail(email);

        User user = existingUserOpt.orElseGet(() -> {
            log.info("User not found. Creating new user: {}", email);
            User newUser = new User();
            newUser.setEmail(email);
            newUser.setUsername(name != null ? name : email.split("@")[0]);
            return userRepository.save(newUser);
        });

        // Generate JWT token
        String token = jwtUtil.generateToken(user.getEmail());
        log.info("Generated JWT token for user: {}", email);

        // Send login notification email
        if (user.getEmail() != null && !user.getEmail().isEmpty()) {
            log.info("Sending login notification to: {}", user.getEmail());
            emailService.sendLoginNotification(user.getEmail());
        } else {
            log.warn("User email is null or empty. Cannot send login notification.");
        }

        // Redirect user to the frontend with the token
        String redirectUrl = "http://localhost:5173/oauth-callback?token=" + token + "&email=" + email;
        log.info("Redirecting to: {}", redirectUrl);
        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }
}
