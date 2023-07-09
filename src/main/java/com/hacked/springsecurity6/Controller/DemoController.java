package com.hacked.springsecurity6.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;

@RestController()
public class DemoController {

    @GetMapping("/demo")
    @PreAuthorize("hasAuthority('read')")
    public String demo() {
        return "demo";
    }

    @GetMapping("/demo2/{name}")
    @PreAuthorize("#name == authentication.name")
    public String demo2(@PathVariable("name") String name) {
        return "Demo: Welcome " + name;
    }

    @GetMapping("/demo3/{name}")
    @PreAuthorize(
            """
            #name == authentication.name or
            hasAnyAuthority("read","write")
            """
    )
    public String demo3(@PathVariable("name") String name) {
        StringBuilder stringBuilder = new StringBuilder("Demo: Welcome ");
        if(Objects.equals(name, SecurityContextHolder.getContext().getAuthentication().getName())) {
            stringBuilder.append(SecurityContextHolder.getContext().getAuthentication().getName());
            stringBuilder.append("/n");
        }
        else {
            stringBuilder.append(name);
            stringBuilder.append("/n");
        }
        return stringBuilder.toString();
    }

    @GetMapping("/demo4/{name}")
    @PreAuthorize("@demo4ConditionValidator.validate(#name)")
    public String demo4(@PathVariable("name") String name) {
        return "demo4";
    }

}
