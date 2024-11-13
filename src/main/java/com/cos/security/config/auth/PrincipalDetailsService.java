package com.cos.security.config.auth;

import com.cos.security.model.User;
import com.cos.security.repository.UserRepository;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 *  Spring Security에서 사용자 인증을 처리
 *  UserDetailsService 인터페이스를 구현하여 데이터베이스에서 사용자 정보를 로드하고,
 *  Security의 세션(Authentication)에 담을 UserDetails 객체를 반환하는 역할
 *
 * 시큐리티 설정에서 loginProcessingUrl("/login");
 * /login 요청이 오면 자동으로 UserDetailsService 타입으로 IoC 되어있는
 * loadUserByUsername 함수가 실행
 * html input에서 username을 바꾸면 loadUserByUsername(String username) 매칭안됨
 * 그럼 SecurityConfig 에 //.usernameParameter("username2") 넣어야함
 */
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    /*
        해당 메소드는 사용자가 로그인 페이지에서 username과 password를 입력하여 로그인 요청을 보내면,
        Spring Security는 자동으로 UserDetailsService 타입으로 등록된 loadUserByUsername 메서드를 호출

        로그인 요청이 들어올 때 username을 기반으로 사용자 정보를 데이터베이스에서 조회하여 인증에 필요한 사용자 정보를 반환하는 역할을 함
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return Optional.ofNullable(userRepository.findByUsername(username))
            .map(PrincipalDetails::new)
            .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
    }
}
