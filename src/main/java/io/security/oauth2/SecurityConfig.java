package io.security.oauth2;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig {

    private final ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests((requests) -> requests.antMatchers("/home").permitAll()
                .anyRequest().authenticated());
        http.oauth2Login(authLogin ->
                authLogin.authorizationEndpoint(authEndpoint ->
                        authEndpoint.authorizationRequestResolver(customOAuth2AuthenticationRequestResolver())));
        http.logout().logoutSuccessUrl("/home");
        return http.build();

//        return http
//                .authorizeRequests(authRequest -> authRequest
//                        .mvcMatchers("/home").permitAll()
//                        .anyRequest().authenticated()
//                )
//                .oauth2Login(withDefaults()
////                        .loginPage("/loginPage")
//
//                )
//                .logout(logout -> logout
//                                .logoutSuccessUrl("/home")
////                        .logoutSuccessHandler(oidcLogoutSuccessHandler())
////                        .invalidateHttpSession(true)
////                        .clearAuthentication(true)
////                        .deleteCookies("JSESSIONID")
//                )
//                .build();
    }

//    private OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler() {
//        OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
//        successHandler.setPostLogoutRedirectUri("http://localhost:8081/login");
//        return successHandler;
//    }

    private OAuth2AuthorizationRequestResolver customOAuth2AuthenticationRequestResolver() {
        return new CustomOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
    }

    @Bean
    public HttpCookieOAuth2AuthorizationRequestRepository cookieAuthorizationRequestRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }


}
