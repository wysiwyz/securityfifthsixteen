package com.februus.newIbankBackend.config;

import com.februus.newIbankBackend.controller.NoticesController;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ProjectSecurityConfig {

    /**
     * 1. paste from SpringBootWebSecurityConfiguration
     * 2. invoke requestMatchers() method
     * 3. invoke and() method to combine different configurations of spring security
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                .requestMatchers("/myAccount","/myBalance","/myLoans","myCards").authenticated() //to protect these api paths
                .requestMatchers("/notices","/contact").permitAll() //everyone can access these api paths
                .and().formLogin()
                .and().httpBasic();

        return http.build();
    }

    /**
     * Approach 2: where we use NoOpPasswordEncoder Bean while creating user details
     */
    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails admin = User.withUsername("admin")
                .password("99999")
                .authorities("admin")
                .build();
        UserDetails user = User.withUsername("user")
                .password("88888")
                .authorities("read")
                .build();
        return new InMemoryUserDetailsManager(admin, user);
    }

    /**
     * Approach 2 is only for non-prod, as it treats password as plain text.
     * @return PasswordEncoder
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
