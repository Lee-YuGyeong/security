package com.cos.security.config.oauth;

import com.cos.security.config.auth.PrincipalDetails;
import com.cos.security.config.oauth.provider.FacebookUserInfo;
import com.cos.security.config.oauth.provider.GoogleUserInfo;
import com.cos.security.config.oauth.provider.NaverUserInfo;
import com.cos.security.config.oauth.provider.OAuth2UserInfo;
import com.cos.security.model.User;
import com.cos.security.repository.UserRepository;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    // OAuth2UserRequest 객체를 받아 OAuth2 로그인 후 사용자 정보를 로드하는 메서드
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 실제로 OAuth2 서비스에서 제공하는 사용자 정보를 가져옴
        OAuth2User oAuth2User = super.loadUser(userRequest);

        //회원가입을 강제로 진행해볼 예정
        OAuth2UserInfo oAuth2UserInfo = null;
        
        // 로그인 진행 중인 서비스(구글, 페이스북, 네이버 .. ) 구분
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        
        if (registrationId.equals("google")) {
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (registrationId.equals("facebook")) {
            oAuth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        } else if (registrationId.equals("naver")) {
            oAuth2UserInfo = new NaverUserInfo((Map<String, Object>) oAuth2User.getAttributes().get("response"));
        } else {
            System.out.println("우리는 구글과 페이스북과 네이버만 지원해요");
        }

        String username = oAuth2UserInfo.getProvider() + "_" + oAuth2UserInfo.getProviderId();
        String password = bCryptPasswordEncoder.encode("default_password");
        String email = oAuth2UserInfo.getEmail();
        String role = "ROLE_USER";

        //사용자가 이미 존재하는지 확인
        User userEntity = userRepository.findByUsername(username);

        if (userEntity == null) {
            System.out.println("Oauth 로그인이 최초입니다.");
            userEntity = registerUser(username, password, email, role, oAuth2UserInfo);
        } else {
            System.out.println("로그인을 이미 한 적이 있습니다. 당신은 자동 로그인이 되었습니다.");
        }

        // PrincipalDetails는 OAuth2User 인터페이스와 UserDetails 인터페이스를 구현하여,
        // Spring Security의 인증 및 권한 부여에 사용
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes());
    }

    private User registerUser(String username, String password, String email, String role,
        OAuth2UserInfo oAuth2UserInfo) {

        User user = User.builder()
            .username(username)
            .password(password)
            .email(email)
            .role(role)
            .provider(oAuth2UserInfo.getProvider())
            .providerId(oAuth2UserInfo.getProviderId())
            .build();

        return userRepository.save(user);
    }
}
