package org.example.spacesback.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Arrays;
import java.util.List;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtFilter;
    private final CustomAuthHandlers.CustomAuthenticationEntryPoint authEntryPoint;
    private final CustomAuthHandlers.CustomAccessDeniedHandler accessDeniedHandler;
    private final List<String> allowedOrigins;

    public SecurityConfig(
            JwtAuthenticationFilter jwtFilter,
            CustomAuthHandlers.CustomAuthenticationEntryPoint authEntryPoint,
            CustomAuthHandlers.CustomAccessDeniedHandler accessDeniedHandler,
            @Value("${app.corsAllowedOrigins:http://localhost:4200}") String corsAllowedOrigins
    ) {
        this.jwtFilter = jwtFilter;
        this.authEntryPoint = authEntryPoint;
        this.accessDeniedHandler = accessDeniedHandler;
        this.allowedOrigins = Arrays.stream(corsAllowedOrigins.split(","))
                .map(String::trim)
                .filter(origin -> !origin.isBlank())
                .toList();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(allowedOrigins);
                    config.setAllowedMethods(List.of("GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"));
                    config.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept", "Origin"));
                    config.setExposedHeaders(List.of("Location"));
                    config.setAllowCredentials(true);
                    config.setMaxAge(3600L);
                    return config;
                }))
                .headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler)
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/auth/**",
                                "/actuator/health",
                                "/h2-console/**",
                                "/h2"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
