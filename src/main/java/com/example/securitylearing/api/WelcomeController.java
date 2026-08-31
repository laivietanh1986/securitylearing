package com.example.securitylearing.api;

import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;

@RestController
public class WelcomeController {

    @GetMapping("/hello")
    public String hello() {
        return "Hello, Welcome!";
    }
}
