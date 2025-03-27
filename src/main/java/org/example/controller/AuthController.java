package org.example.controller;

import org.example.dto.UserDTO;
import org.example.entities.User;
import org.example.repository.UserRepository;
import org.example.service.AuthService;
import org.example.dto.AuthRequest;
import org.example.dto.AuthResponse;
import org.example.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    private UserRepository userRepository;

    private final AuthService authService;
    private final JwtUtil jwtUtil;

    public AuthController(AuthService authService, JwtUtil jwtUtil) {
        this.authService = authService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        try {
            if (request.getUsernameOrEmail() == null || request.getPassword() == null) {
                return ResponseEntity.badRequest().body("Username/email and password are required");
            }

            String token = authService.login(request.getUsernameOrEmail(), request.getPassword());
            return ResponseEntity.ok(new AuthResponse(token));

        } catch (RuntimeException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("{\"error\": \"" + e.getMessage() + "\"}");

        }
    }

    // Add this new endpoint for frontend to get user details
    @GetMapping("/me")
    public ResponseEntity<UserDTO> getCurrentUser(@RequestHeader("Authorization") String token) {
        String jwt = token.replace("Bearer ", "");
        String email = jwtUtil.extractUsername(jwt);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return ResponseEntity.ok(new UserDTO(user));
    }
}