package tp.social.config;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import tp.social.user.UserRegistrationService;

@Service
@RequiredArgsConstructor
public class GoogleOAuth2UserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final UserRegistrationService userRegistrationService;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUserService oidcUserService = new OidcUserService();
        OidcUser oidcUser = oidcUserService.loadUser(userRequest);
        OAuth2AccessToken accessToken = userRequest.getAccessToken();

        String name = oidcUser.getAttributes().get("name").toString();
        String email = oidcUser.getAttributes().get("email").toString();

        userRegistrationService.requestRegistration(name, email);
        return new DefaultOidcUser(
                oidcUser.getAuthorities(),
                oidcUser.getIdToken(),
                oidcUser.getUserInfo()
        );
    }
}
