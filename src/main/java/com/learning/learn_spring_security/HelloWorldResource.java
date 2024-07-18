package com.learning.learn_spring_security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldResource {
    @GetMapping(path="/hello-world")
    public String helloWorld(){
        return "hello world";
    }
}
