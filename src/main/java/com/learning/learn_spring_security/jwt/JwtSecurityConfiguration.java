package com.learning.learn_spring_security.jwt;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.sql.DataSource;

import com.learning.learn_spring_security.basic.Roles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION;

@Configuration
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
public class JwtSecurityConfiguration {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(
                auth -> {
                    auth
                            .anyRequest().authenticated();
                });

        http.sessionManagement(
                session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS)
        );

        //http.formLogin();
        // Because of this now login and logout page/feature has been removed.
        //http.csrf(AbstractHttpConfigurer::disable);
        http.csrf(csrf -> csrf.disable());
        http.headers(headers -> headers.frameOptions(frameOptionsConfig-> frameOptionsConfig.disable()));
        http.oauth2ResourceServer(oauth2 ->
                oauth2.jwt(withDefaults())
        );
        http.httpBasic(withDefaults());

        return http.build();
    }

    // Storing User Credentials:
    /*
     * In Memory : For test purposes. Not recommend in production (application.properties).
     * Database : We can use JDBC/JPA to access the credentials.
     * LDAP : Lightweight Directory Access Protocol.
     * */

    @Bean
    public DataSource dataSource(){
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
        // The addScript points to a script users.ddl which runs and set up the database for user details.
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource){
        Roles USER = Roles.USER;
        Roles ADMIN = Roles.ADMIN;

        var user = User.withUsername("suryanshu")
                //.password("{noop}dummy")
                .password("dummy")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles(USER.toString())
                .build();
        // {noop} => To not use any encoding we are using this.

        var admin = User.withUsername("admin")
                //.password("{noop}dummy")
                .password("dummy")
                .passwordEncoder(str -> passwordEncoder().encode(str))
                .roles(ADMIN.toString())
                .build();

        // Now we are using jdbcUserDetailsManager to manage
        //return new InMemoryUserDetailsManager(user,admin);

        //Jdbc user management service, based on the same table structure as its parent class, JdbcDaoImpl.
        var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);

        return jdbcUserDetailsManager;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Configure a Decoder for JWT Token.

    // 1 . Generating a key-pair.
    // Used java.security.KeyPairGenerator.
    @Bean
    public KeyPair keyPair() throws NoSuchAlgorithmException {
        var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
    // 2. Create RSA key object using Key Pair.
        // Used com.nimbusds.jose.RSAKey
    @Bean
    public RSAKey rsaKey(KeyPair keyPair){
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey(keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    //3. Create JWKSource(JSON Web Key Source)
    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey){
        //a . Create JWKSet (a new JSON Web Key Set) with the RSA Key.
        var jwkSet = new JWKSet(rsaKey);
        //b. Create JWK using the JWKSet.
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
//        var jwkSource = new JWKSource(){
//
//            @Override
//            public List get(JWKSelector jwkSelector, SecurityContext securityContext) throws KeySourceException {
//                return jwkSelector.select(null);
//            }
//        };
//        return jwkSource;
    }
    //4 . Use RSA Public Key for Decoding.
    @Bean
    public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
        return NimbusJwtDecoder
                .withPublicKey(rsaKey.toRSAPublicKey()).build();
    }
    // 5. Use JWKSource for Encoding.
    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource){
        return new NimbusJwtEncoder(jwkSource);
    }
}
