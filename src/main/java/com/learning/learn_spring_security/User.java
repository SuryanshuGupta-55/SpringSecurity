package com.learning.learn_spring_security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class User {
    @GetMapping(path = "/")
    public String welcomeUser(){
        return "Welcome";
    }

    @GetMapping(path = "/{username}")
    public String welcomeName(@PathVariable String username){
        return "Welcome " + username;
    }
}
