package kh.edu.istad.springauthorizationserver.oauth.client;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Entity
@Table(
        name = "oauth2_clients",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_oauth2_clients_client_id",
                columnNames = "client_id"
        )
)
@Getter
@Setter
@NoArgsConstructor
public class ClientEntity {

    @Id
    @Column(nullable = false, length = 100)
    private String id;

    @Column(name = "client_id", nullable = false, unique = true, length = 200)
    private String clientId;

    @Column(name = "client_id_issued_at", nullable = false)
    private Instant clientIdIssuedAt;

    @Column(name = "client_secret", length = 1000)
    private String clientSecret;

    @Column(name = "client_name", nullable = false, length = 200)
    private String clientName;

    @Column(name = "client_authentication_methods", nullable = false, length = 1000)
    private String clientAuthenticationMethods;

    @Column(name = "authorization_grant_types", nullable = false, length = 1000)
    private String authorizationGrantTypes;

    @Column(name = "redirect_uris", length = 2000)
    private String redirectUris;

    @Column(name = "post_logout_redirect_uris", length = 2000)
    private String postLogoutRedirectUris;

    @Column(nullable = false, length = 2000)
    private String scopes;

    @Column(nullable = false)
    private boolean requireAuthorizationConsent;

    @Column(nullable = false)
    private boolean requireProofKey = true;
}