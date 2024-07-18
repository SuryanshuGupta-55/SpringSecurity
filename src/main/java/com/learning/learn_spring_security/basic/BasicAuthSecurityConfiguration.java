package com.learning.learn_spring_security.basic;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
public class BasicAuthSecurityConfiguration {
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
    public UserDetailsService userDetailsService(){
        Roles USER = Roles.USER;
        Roles ADMIN = Roles.ADMIN;

        var user = User.withUsername("suryanshu")
                .password("{noop}dummy")
                .roles(USER.toString())
                .build();
        // {noop} => To not use any encoding we are using this.

        var admin = User.withUsername("admin")
                .password("{noop}dummy")
                .roles(ADMIN.toString())
                .build();

        return new InMemoryUserDetailsManager(user,admin);
    }
}
