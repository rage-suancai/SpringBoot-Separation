package com.bootbackend.NoStatus.config;

import com.bootbackend.NoStatus.filter.JwtAuthenticationFilter;
import com.bootbackend.NoStatus.tool.jwt.JwtUtils;
import com.bootbackend.NoStatus.tool.rest.RestBean17;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.AccessDeniedException;

@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        return http
                .authorizeHttpRequests(conf -> {
                    conf.anyRequest().authenticated();
                })
                .formLogin(conf -> {
                    conf.loginProcessingUrl("/api/auth/login");
                    conf.failureHandler(this::handleProcess);
                    conf.successHandler(this::handleProcess);
                    conf.permitAll();
                })
                .logout(conf -> {
                    conf.logoutUrl("/api/auth/logout");
                    conf.logoutSuccessHandler(this::onLogoutSuccess);
                })
                .exceptionHandling(conf -> {
                    conf.accessDeniedHandler(this::handleProcess);
                    conf.authenticationEntryPoint(this::handleProcess);
                })
                .cors(conf -> {
                    CorsConfiguration cors = new CorsConfiguration();
                    cors.addAllowedOrigin("http://localhost:8080"); cors.setAllowCredentials(false);
                    cors.addAllowedHeader("*"); cors.addAllowedMethod("*"); cors.addExposedHeader("*");
                    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                    source.registerCorsConfiguration("/**", cors);
                    conf.configurationSource(source);
                })
                .sessionManagement(conf -> {
                    conf.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })
                .addFilterBefore(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .build();

    }

    private void handleProcess(HttpServletRequest request,
                               HttpServletResponse response,
                               Object exceptionOrAuthentication) throws IOException {

        response.setContentType("application/json;charset=utf-8"); PrintWriter writer = response.getWriter();

        if (exceptionOrAuthentication instanceof AccessDeniedException e)
            writer.write(RestBean17.failure(403, e.getMessage()).asJsonString());
        else if (exceptionOrAuthentication instanceof Exception e)
            writer.write(RestBean17.failure(401, e.getMessage()).asJsonString());
        else if (exceptionOrAuthentication instanceof Authentication authentication)
            writer.write(RestBean17.success(JwtUtils.createJwt((User) authentication.getPrincipal())).asJsonString());

    }

    private void onLogoutSuccess(HttpServletRequest request,
                                 HttpServletResponse response,
                                 Authentication authentication) throws IOException {

        response.setContentType("application/json;charset=utf-8"); PrintWriter writer = response.getWriter();

        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.startsWith("Bearer ")) {
            String token = authorization.substring(7);
            if (JwtUtils.invalidate(token)) writer.write(RestBean17.success("退出登录成功").asJsonString()); return;
        }
        writer.write(RestBean17.failure(400, "退出登录失败").asJsonString());

    }

}
