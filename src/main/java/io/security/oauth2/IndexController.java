package io.security.oauth2;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class IndexController {

    private final ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping("/")
    public String index() {

        return "index";
    }


    @GetMapping("/user")
    public OAuth2User user(String accessToken) {

        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");

        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX);

        OAuth2UserRequest oAuth2UserRequest = new OAuth2UserRequest(clientRegistration, oAuth2AccessToken);


        DefaultOAuth2UserService defaultOAuth2UserService = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = defaultOAuth2UserService.loadUser(oAuth2UserRequest);

        return oAuth2User;
    }

    @GetMapping("/oidc")
    public OAuth2User oidc(String accessToken, String idToken) {

        ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");

        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX);

        Map<String, Object> claims = new HashMap<>();
        claims.put(IdTokenClaimNames.ISS, "http://localhost:8080/realms/oauth2");
        claims.put(IdTokenClaimNames.SUB, "OIDC0");
        claims.put("preferred_username", "user");

        OidcIdToken oidcIdToken = new OidcIdToken(idToken, Instant.now(), Instant.MAX, claims);

        OidcUserRequest oAuth2UserRequest = new OidcUserRequest(clientRegistration, oAuth2AccessToken, oidcIdToken);
        OidcUserService oidcUserService = new OidcUserService();

        OidcUser oidcUser = oidcUserService.loadUser(oAuth2UserRequest);

        return oidcUser;
    }
}
