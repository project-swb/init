package com.swb.config.auth;

import com.swb.domain.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .headers(header -> header.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))
                .authorizeHttpRequests(
                        registry -> registry.requestMatchers(new AntPathRequestMatcher("/"),new AntPathRequestMatcher("/images/**")
                                        ,new AntPathRequestMatcher("/js/**"), new AntPathRequestMatcher("/h2-console/**"))
                                    .permitAll()
                                    .requestMatchers(new AntPathRequestMatcher("/api/v1/**")).hasRole(Role.USER.name())
                                    .anyRequest()
                                    .authenticated()
                )
                .logout(logout->logout.logoutSuccessUrl("/"))
                .oauth2Login(oauth2Login->oauth2Login.userInfoEndpoint(endpoint -> endpoint.userService(customOAuth2UserService)));


        return http.build();
    }

}

