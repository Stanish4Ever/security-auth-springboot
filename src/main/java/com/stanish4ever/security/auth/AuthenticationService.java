package com.stanish4ever.security.auth;

import com.stanish4ever.security.config.JWTService;
import com.stanish4ever.security.user.Role;
import com.stanish4ever.security.user.User;
import com.stanish4ever.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JWTService jwtService;
    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER).build();

        repository.save(user);
        var jwtToken =  jwtService.generateToken(user);
        return AuthenticationResponse.builder().token(jwtToken).build();

//        return null;
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(), request.getPassword()
                )
        );
        var user = repository.findByEmail(request.getEmail()).orElseThrow(null);
        var jwtToken =  jwtService.generateToken(user);
        return AuthenticationResponse.builder().token(jwtToken).build();
    }
}
