package com.hacked.springsecurity6.Config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@ConditionalOnProperty("security-enable-basic-security")
public class SecurityConfig {

    @EnableMethodSecurity()
    @ConditionalOnProperty("security-in-memory")
    @Order(1)
    public class InMemorySecurity {
        @Bean
        @ConditionalOnProperty("security-in-memory")
        public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
            httpSecurity
                    .httpBasic()
                    .and()
                    .authorizeHttpRequests()
                    .anyRequest()
                    .authenticated();
            return httpSecurity.build();
        }

        @Bean
        public UserDetailsService userDetailsService() {
            UserDetails userDetails = User.withUsername("bob")
                    .password(passwordEncoder().encode("12345"))
                    .authorities("read","write","share")
                    .build();

            InMemoryUserDetailsManager uds = new InMemoryUserDetailsManager();
            uds.createUser(userDetails);

            return uds;
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
            return new BCryptPasswordEncoder(8);
        }
    }

    @EnableMethodSecurity(prePostEnabled = false)
    @ConditionalOnProperty("security-no-security")
    @Order(1)
    public class NoSecurity {

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
            httpSecurity
                    .authorizeHttpRequests()
                    .anyRequest().permitAll();
            return httpSecurity.build();
        }
    }

}
