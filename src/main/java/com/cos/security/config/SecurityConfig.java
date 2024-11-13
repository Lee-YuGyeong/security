package com.cos.security.config;

import com.cos.security.config.oauth.PrincipalOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity //스프링 시큐리티 필터가 스프링 필터 체인에 등록된다.
@EnableMethodSecurity(securedEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    // OAuth2 인증 후 사용자 정보를 처리하는 서비스
    private final PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)  //CSRF 보호 기능을 비활성화 (테스트 환경 또는 API 서버에서 주로 비활성화)
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/user/**").authenticated() // 인증만 되면 들어갈 수 있는 주소
                .requestMatchers("/manager/**").hasAnyRole("MANAGER", "ADMIN") // manager으로 들어오는 MANAGER 인증 또는 ADMIN인증이 필요하다는 뜻이다.
                .requestMatchers("/admin/**").hasRole("ADMIN") // admin으로 들어오면 ADMIN권한이 있는 사람만 들어올 수 있음
                .anyRequest().permitAll() // 그리고 나머지 url은 전부 권한을 허용해준다.
            ).formLogin(form -> form //권한이 필요한 경우 로그인 페이지로 이동함
                .loginPage("/loginForm")
                //.usernameParameter("username2")
                .loginProcessingUrl("/login") // login 주소가 호출이 되면 시큐리티가 자동으로 로그인을 진행해준다.
                .defaultSuccessUrl("/") // 로그인 성공 후 리다이렉트할 기본 URL을 설정
            ) //oauth 로그인페이지나 일반 로그인페이지나 똑같이 설정
            .oauth2Login(oauth2Login -> oauth2Login.loginPage("/loginForm")
                .userInfoEndpoint( // OAuth 인증 후 사용자 정보를 받아 처리
                    userInfoEndpoint -> userInfoEndpoint.userService(principalOauth2UserService)));

        return http.build();
    }
}