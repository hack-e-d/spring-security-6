package com.hacked.springsecurity6.AuthorizationServer.Entities;

import jakarta.persistence.*;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@Entity
@Table(name = "clients",schema = "springsecurity6")
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String clientId;

    private String secret;

    private String redirectUri;

    private String scope;

    private String authMethod;

    private String grantType;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getAuthMethod() {
        return authMethod;
    }

    public void setAuthMethod(String authMethod) {
        this.authMethod = authMethod;
    }

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public static Client from(RegisteredClient registeredClient) {
        Client client = new Client();

        client.setClientId(registeredClient.getClientId());
        client.setSecret(registeredClient.getClientSecret());
        client.setRedirectUri(registeredClient.getRedirectUris().stream().findAny().get());
        client.setScope(registeredClient.getScopes().stream().findAny().get());
        client.setAuthMethod(registeredClient.getClientAuthenticationMethods().stream().findAny().get().getValue());
        client.setGrantType(registeredClient.getAuthorizationGrantTypes().stream().findAny().get().getValue());
        return client;
    }

    public static RegisteredClient from(Client client) {
        return RegisteredClient
                .withId(String.valueOf(client.getId()))
                .clientId(client.getClientId())
                .clientSecret(client.getSecret())
                .clientAuthenticationMethod(new ClientAuthenticationMethod(client.getAuthMethod()))
                .scope(client.getScope())
                .redirectUri(client.getRedirectUri())
                .authorizationGrantType(new AuthorizationGrantType(client.getGrantType()))
                .build();
    }
}
