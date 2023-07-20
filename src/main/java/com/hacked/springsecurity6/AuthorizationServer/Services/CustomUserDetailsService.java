package com.hacked.springsecurity6.AuthorizationServer.Services;

import com.hacked.springsecurity6.AuthorizationServer.Entities.User;
import com.hacked.springsecurity6.AuthorizationServer.Models.SecurityUser;
import com.hacked.springsecurity6.AuthorizationServer.Repositories.UserRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

/*
 * @Author vijaypv
 * password => 12345
 */
@ConditionalOnProperty("security-authorization-server-database")
@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByUsername(username);
        return user.map(SecurityUser::new).orElseThrow(() ->new UsernameNotFoundException(":("));
    }
}
