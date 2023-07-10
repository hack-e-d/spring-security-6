package com.hacked.springsecurity6.Controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@RestController()
public class DemoController {

    Logger logger = LoggerFactory.getLogger(DemoController.class);
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

//    @PostAuthorize
    @GetMapping("/demo5")
    @PostAuthorize("hasAuthority('match')")
    public String demo5() {
        logger.info("Post Authorize method called");
        return "Demo5: Post Authorize";
    }

//    @PreFilter => works best with either array or Collection
    @GetMapping("demo6")
    @PreFilter("filterObject.contains('a')")
    public String demo6(@RequestBody List<String> values)   {
        return "Demo: PreFilter";
    }

//    @PostFilter => not so recommended as it doesn't find much use case
//    @PostFilter filter the return value unlike @PreFilter which filters the incoming input value
    @GetMapping("demo7")
    @PostFilter("filterObject.contains('a')")
    public List<String> demo7() {
        return  new ArrayList<>(Arrays.asList("asd", "aswe","dfghj","awwq"));
    }
}
