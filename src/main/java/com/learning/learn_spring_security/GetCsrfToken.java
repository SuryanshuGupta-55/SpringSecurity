package com.learning.learn_spring_security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// SpringSecurityPlayResource
@RestController
public class GetCsrfToken {
    @GetMapping(path = "/csrf-token")
    public CsrfToken getCsrfToken(HttpServletRequest request){
        return (CsrfToken) request.getAttribute("_csrf");
    }
}

/*
*  O/p for above endpoint:
*   {
        "parameterName": "_csrf",
        "headerName": "X-CSRF-TOKEN",
        "token": "dBR7b3EfygEPob_ecqagr5rynVIpbmR6tfaMIOUT507y7PDlECxMWkR6_WMimInpRouUyq6RsDMcVgZXjM7oFYAl3n_C2MCD"
    }
* */