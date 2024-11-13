package com.cos.security.config.auth;

import com.cos.security.model.User;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * 시큐리티가 /login 주소 요청이 오면 낚아채서 로그인을 진행시킨다.
 * 로그인 진행이 완료가 되면 시큐리티 session을 만들어줍니다. (Security ContextHolder)
 * 오브젝트 타입 => Authentication 타입 객체
 * Authentication 안에 User 정보가 있어야 됨
 * User 오브젝트 타입 => UserDetails 타입 객체
 *
 * Security Session => Authentication => UserDetails(PrincipalDetails)

    Spring Security에서 사용자 인증과 권한 관리를 담당
    UserDetails와 OAuth2User 인터페이스를 구현하여 일반 로그인과 OAuth 로그인 두 가지 방식을 지원
 */
@Data
public class PrincipalDetails implements UserDetails, OAuth2User {
    private User user;
    private Map<String, Object> attributes; // OAuth2 로그인 시 제공되는 사용자 정보 속성들을 저장하는 맵

    //일반 로그인용 생성자, User 객체를 초기화
    public PrincipalDetails(User user) {
        this.user = user;
    }

    //oauth 로그인용 생성자, User 객체와 사용자 속성 맵을 초기화
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    //사용자의 권한을 Collection 형태로 반환
    //GrantedAuthority 객체를 생성하여 User.getRole()로 설정된 권한을 제공
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of((GrantedAuthority) () -> user.getRole());
    }

    // 사용자 비밀번호 반환 (UserDetails의 메서드)
    @Override
    public String getPassword() {
        return user.getPassword();
    }

    // 사용자 이름 반환 (UserDetails의 메서드)
    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 게정이 만료되지 않았는지
    @Override
    public boolean isAccountNonExpired() { return true; }

    // 계정이 잠기지 않았는지
    @Override
    public boolean isAccountNonLocked() { return true; }

    // 자격증명이 만료되지 않았는지
    @Override
    public boolean isCredentialsNonExpired() { return true; }

    //계정이 활성화 상태인지
    @Override
    public boolean isEnabled() { return true; }

    // OAuth2 사용자 정보 속성 맵을 반환 (일반 로그인에서는 null)
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    // OAuth2 로그인 시 사용자의 이름을 반환
    @Override
    public String getName() {
        return null;
    }
}
