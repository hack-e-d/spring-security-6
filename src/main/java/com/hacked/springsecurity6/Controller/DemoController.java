package com.hacked.springsecurity6.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController()
public class DemoController {

    @GetMapping("/demo")
    @PreAuthorize("hasAuthority('read')")
    public String demo() {
        return "demo";
    }
}
