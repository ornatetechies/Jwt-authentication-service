package com.ornate.authorization_authentication.service;

import com.ornate.authorization_authentication.model.UserEntity;
import com.ornate.authorization_authentication.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

@Service public class ServiceImpl {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    JwtEncoder jwtEncoder;
    @Autowired
    private PasswordEncoder passwordEncoder;

    public String registerUser(UserEntity user){
        Optional<UserEntity> userEntity = userRepository.findByUsername(user.getUsername());
        if (userEntity.isPresent()){
            return "Username already taken";
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRole("ROLE_USER");
        userRepository.save(user);

        return "User Registered successfully";
    }

    public Map<String, Object> login(String username, String password) {
        Optional<UserEntity> userEntity = userRepository.findByUsername(username);
        Map<String, Object> response = new HashMap<>();

        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        if (!userEntity.isPresent()){
            response.put("status", "User Not Found");
            return response;
        }
        String accessToken = generateToken(userEntity.get(), authentication, 3600);
        response.put("access_token", accessToken);
        response.put("expires_in", 3600);
        return response;
    }

    private String generateToken(UserEntity userEntity, Authentication authentication, long expiryDuration){
        Instant now = Instant.now();
        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuer("Ornate")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiryDuration))
                .subject(authentication.getName())
                .claim("role", authentication.getAuthorities().toString())
                .claim("firstName", userEntity.getFirstName())
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();

    }
}
