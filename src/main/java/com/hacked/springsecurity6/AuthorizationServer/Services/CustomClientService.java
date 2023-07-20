package com.hacked.springsecurity6.AuthorizationServer.Services;

import com.hacked.springsecurity6.AuthorizationServer.Entities.Client;
import com.hacked.springsecurity6.AuthorizationServer.Repositories.ClientRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

/*
* @Author vijaypv
* Secret => secret@dev
*/
@ConditionalOnProperty("security-authorization-server-database")
@Service
public class CustomClientService implements RegisteredClientRepository {

    private final ClientRepository clientRepository;

    public CustomClientService(ClientRepository clientRepository) {
        this.clientRepository = clientRepository;
    }
    @Override
    public void save(RegisteredClient registeredClient) {
        clientRepository.save(Client.from(registeredClient));
    }

    @Override
    public RegisteredClient findById(String id) {
        return Client.from(clientRepository.findById(Integer.valueOf(id)).orElseThrow());
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return Client.from(clientRepository.findByClientId(clientId).orElseThrow());
    }
}
