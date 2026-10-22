package kh.edu.istad.springauthorizationserver.oauth.client;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Repository
@RequiredArgsConstructor
@Transactional
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

    private final ClientRepository clientRepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        ClientEntity entity = clientRepository
                .findById(registeredClient.getId())
                .orElseGet(ClientEntity::new);

        entity.setId(registeredClient.getId());
        entity.setClientId(registeredClient.getClientId());
        entity.setClientIdIssuedAt(
                registeredClient.getClientIdIssuedAt() != null
                        ? registeredClient.getClientIdIssuedAt()
                        : Instant.now()
        );
        entity.setClientSecret(registeredClient.getClientSecret());
        entity.setClientName(registeredClient.getClientName());

        entity.setClientAuthenticationMethods(
                join(registeredClient.getClientAuthenticationMethods()
                        .stream()
                        .map(ClientAuthenticationMethod::getValue)
                        .collect(Collectors.toSet()))
        );

        entity.setAuthorizationGrantTypes(
                join(registeredClient.getAuthorizationGrantTypes()
                        .stream()
                        .map(AuthorizationGrantType::getValue)
                        .collect(Collectors.toSet()))
        );

        entity.setRedirectUris(join(registeredClient.getRedirectUris()));
        entity.setPostLogoutRedirectUris(
                join(registeredClient.getPostLogoutRedirectUris())
        );
        entity.setScopes(join(registeredClient.getScopes()));

        entity.setRequireAuthorizationConsent(
                registeredClient.getClientSettings()
                        .isRequireAuthorizationConsent()
        );

        entity.setRequireProofKey(
                registeredClient.getClientSettings().isRequireProofKey()
        );

        clientRepository.save(entity);
    }

    @Override
    @Transactional(readOnly = true)
    public RegisteredClient findById(String id) {
        return clientRepository.findById(id)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public RegisteredClient findByClientId(String clientId) {
        return clientRepository.findByClientId(clientId)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    private RegisteredClient toRegisteredClient(ClientEntity entity) {
        RegisteredClient.Builder builder = RegisteredClient
                .withId(entity.getId())
                .clientId(entity.getClientId())
                .clientIdIssuedAt(entity.getClientIdIssuedAt())
                .clientName(entity.getClientName())
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(
                                entity.isRequireAuthorizationConsent()
                        )
                        .requireProofKey(entity.isRequireProofKey())
                        .build())
                .tokenSettings(TokenSettings.builder().build());

        if (entity.getClientSecret() != null) {
            builder.clientSecret(entity.getClientSecret());
        }

        parse(entity.getClientAuthenticationMethods())
                .forEach(value -> builder.clientAuthenticationMethod(
                        new ClientAuthenticationMethod(value)
                ));

        parse(entity.getAuthorizationGrantTypes())
                .forEach(value -> builder.authorizationGrantType(
                        new AuthorizationGrantType(value)
                ));

        parse(entity.getRedirectUris())
                .forEach(builder::redirectUri);

        parse(entity.getPostLogoutRedirectUris())
                .forEach(builder::postLogoutRedirectUri);

        parse(entity.getScopes()).forEach(builder::scope);

        return builder.build();
    }

    private String join(Set<String> values) {
        return values == null
                ? ""
                : values.stream()
                .sorted()
                .collect(Collectors.joining(","));
    }

    private Set<String> parse(String values) {
        if (!StringUtils.hasText(values)) {
            return Set.of();
        }

        return Arrays.stream(values.split(","))
                .map(String::trim)
                .filter(StringUtils::hasText)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }
}