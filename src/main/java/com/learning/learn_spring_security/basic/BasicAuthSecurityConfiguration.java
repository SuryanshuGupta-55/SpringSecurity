package com.learning.learn_spring_security.basic;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION;

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
        http.headers(headers -> headers.frameOptions(frameOptionsConfig-> frameOptionsConfig.disable()));
        http.httpBasic(withDefaults());

        return http.build();
    }
    
    // Storing User Credentials:
    /*
    * In Memory : For test purposes. Not recommend in production (application.properties).
    * Database : We can use JDBC/JPA to access the credentials.
    * LDAP : Lightweight Directory Access Protocol.
    * */

//    @Bean
//    public UserDetailsService userDetailsService(){
//        Roles USER = Roles.USER;
//        Roles ADMIN = Roles.ADMIN;
//
//        var user = User.withUsername("suryanshu")
//                .password("{noop}dummy")
//                .roles(USER.toString())
//                .build();
//        // {noop} => To not use any encoding we are using this.
//
//        var admin = User.withUsername("admin")
//                .password("{noop}dummy")
//                .roles(ADMIN.toString())
//                .build();
//
//        return new InMemoryUserDetailsManager(user,admin);
//    }

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
                .password("{noop}dummy")
                .roles(USER.toString())
                .build();
        // {noop} => To not use any encoding we are using this.

        var admin = User.withUsername("admin")
                .password("{noop}dummy")
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
}
