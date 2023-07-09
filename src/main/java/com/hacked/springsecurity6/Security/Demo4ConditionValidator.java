package com.hacked.springsecurity6.Security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class Demo4ConditionValidator {

    public boolean validate(String name) {
//        return true;
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return name.equals(authentication.getName()) && !authentication.getAuthorities().isEmpty();
    }
}
