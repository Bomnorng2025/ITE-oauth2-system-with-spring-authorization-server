package kh.edu.istad.springauthorizationserver.oauth.client;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.time.Instant;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class OAuth2ClientInitializer {

    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;

    @Bean
    ApplicationRunner initializeOAuth2Client() {
        return args -> {
            if (registeredClientRepository.findByClientId("oidc-client") != null) {
                return;
            }

            RegisteredClient client = RegisteredClient
                    .withId(UUID.randomUUID().toString())
                    .clientId("oidc-client")
                    .clientIdIssuedAt(Instant.now())
                    .clientSecret(passwordEncoder.encode("secret"))
                    .clientName("OIDC Demo Client")
                    .clientAuthenticationMethod(
                            ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                    )
                    .authorizationGrantType(
                            AuthorizationGrantType.AUTHORIZATION_CODE
                    )
                    .authorizationGrantType(
                            AuthorizationGrantType.REFRESH_TOKEN
                    )
                    .redirectUri(
                            "http://localhost:8080/login/oauth2/code/oidc-client"
                    )
                    .postLogoutRedirectUri("http://localhost:8080/")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .clientSettings(ClientSettings.builder()
                            .requireAuthorizationConsent(true)
                            .requireProofKey(true)
                            .build())
                    .build();

            registeredClientRepository.save(client);
        };
    }
}