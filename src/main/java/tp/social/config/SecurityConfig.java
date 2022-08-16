package tp.social.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Arrays;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@RequiredArgsConstructor
//@EnableWebSecurity
public class SecurityConfig {

    private final Environment environment;
    private final FacebookOAuth2UserService facebookOAuth2UserService;
    private final GoogleOAuth2UserService googleOAuth2UserService;
    private final String registration = "spring.security.oauth2.client.registration.";


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .headers().frameOptions().disable().and()
                .authorizeHttpRequests((authorize) -> authorize
                        .antMatchers("/login","index").permitAll()
                        .anyRequest().authenticated()
                )
//                .oauth2Login(withDefaults())
                .oauth2Login(oauth2 -> oauth2
                        .clientRegistrationRepository(clientRegistrationRepository())
                        .authorizedClientService(authorizedClientService())
                        .userInfoEndpoint( user -> user
                                .oidcUserService(googleOAuth2UserService)  // google 인증, OpenID Connect 1.0
                                .userService(facebookOAuth2UserService)  // facebook 인증, OAuth2 통신
                        )
                )
        ;
        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/h2-console/**");
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        List<ClientRegistration> clientRegistrations = Arrays.asList(
                googleClientRegistration(),
                facebookClientRegistration()
        );

        return new InMemoryClientRegistrationRepository(clientRegistrations);
    }

    private ClientRegistration googleClientRegistration() {
        final String clientId = environment.getProperty(registration + "google.client-id");
        final String clientSecret = environment.getProperty(registration + "google.client-secret");

        return CommonOAuth2Provider
                .GOOGLE
                .getBuilder("google")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .build();
    }

    private ClientRegistration facebookClientRegistration() {
        final String clientId = environment.getProperty(registration + "facebook.client-id");
        final String clientSecret = environment.getProperty(registration + "facebook.client-secret");

        return CommonOAuth2Provider
                .FACEBOOK
                .getBuilder("facebook")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .scope(
                        "public_profile",
                        "email",
                        "user_birthday",
                        "user_gender"
                )
                .userInfoUri("https://graph.facebook.com/me?fields=id,name,email,picture,gender,birthday")
                .build();
    }

}
