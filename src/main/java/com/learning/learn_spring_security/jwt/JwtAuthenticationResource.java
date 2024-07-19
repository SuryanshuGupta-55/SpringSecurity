package com.learning.learn_spring_security.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.stream.Collectors;

@RestController
public class JwtAuthenticationResource {
    private final JwtEncoder jwtEncoder;
    // Step1 : Setup the JwtEncoder.
    public JwtAuthenticationResource(JwtEncoder jwtEncoder){
        this.jwtEncoder = jwtEncoder;
    }
    // Step2 : Setting the endpoint for getting the token.
    @PostMapping(path = "/authenticate")
    public JwtResponse authenticate(Authentication authentication){
        // We will be creating JwtResponse from authentication object.
        return new JwtResponse(createToken(authentication));
    }
    // Step3 : Creating the token by gathering all information from authentication object.
    private String createToken(Authentication authentication){
        // Details Required for creating the token.
        var claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60 * 30))
                .subject(authentication.getName())
                .claim("scope", createScope(authentication))
                .build();
        //System.out.println("claims = " + claims);
        // Creating Parameter from claims.
        JwtEncoderParameters parameters = JwtEncoderParameters.from(claims);
        // This method requires parameters.
        //System.out.println("authentication Principals = " + authentication.getPrincipal());
        //System.out.println("authentication = " + authentication);
        //System.out.println("parameters = " + parameters);
        return jwtEncoder.encode(parameters).getTokenValue();
    }
    // Step 3.a : Getting info from authentication object of Authorities for creating the token as they can be multiple and requires operation.
    // This method helps in getting all authorities, i.e Roles such as ADMIN, USER.
    private String createScope(Authentication authentication) {
        String res =  authentication.getAuthorities().stream()
                .map(a -> a.getAuthority())
                .collect(Collectors.joining(" "));
        System.out.println(" : " + res);
        return res;
    }


}

record JwtResponse(String token){
}