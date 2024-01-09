package com.februus.newIbankBackend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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
//        http.authorizeHttpRequests()
//                .requestMatchers("/myAccount","/myBalance","/myLoans","myCards").authenticated() //to protect these api paths
//                .requestMatchers("/notices","/contact").permitAll() //everyone can access
//                .and().formLogin()
//                .and().httpBasic();
        http.authorizeHttpRequests()
                .anyRequest().permitAll()
                .and().formLogin()
                .and().httpBasic();

        return http.build();
    }
}
