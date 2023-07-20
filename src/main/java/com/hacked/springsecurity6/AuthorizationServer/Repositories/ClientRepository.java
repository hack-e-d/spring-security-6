package com.hacked.springsecurity6.AuthorizationServer.Repositories;

import com.hacked.springsecurity6.AuthorizationServer.Entities.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface ClientRepository extends JpaRepository<Client, Integer> {

//    Advisable to write query but in spring jpa and type of filed can be used to find the value
    @Query("""
        SELECT c FROM Client c WHERE c.clientId = :clientId
    """)
    Optional<Client> findByClientId(String clientId);
}
