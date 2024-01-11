package com.februus.newibankbackend.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class ProjectSecurityConfig {

    /**
     * 1. paste from SpringBootWebSecurityConfiguration
     * 2. invoke requestMatchers() method
     * 3. invoke and() method to combine different configurations of spring security
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeHttpRequests()
                .requestMatchers("/myAccount","/myBalance","/myLoans","myCards").authenticated() //to protect these api paths
                .requestMatchers("/notices","/contact","/register").permitAll() //everyone can access these api paths
                .and().formLogin()
                .and().httpBasic();

        return http.build();
    }

    /**
     * B-Crypt hashing algorithm
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
