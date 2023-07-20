package com.hacked.springsecurity6.AuthorizationServer.Utils;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordEncoder {

    private final String password = "12345";
    public static void main(String[] args) {
        System.out.println(new BCryptPasswordEncoder(8).encode(new PasswordEncoder().password));
    }
}
