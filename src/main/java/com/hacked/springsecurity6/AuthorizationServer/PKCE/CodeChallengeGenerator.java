package com.hacked.springsecurity6.AuthorizationServer.PKCE;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;

public class CodeChallengeGenerator {

    public static void main(String[] args) {

        try {

            PKCEUtil pkce = new PKCEUtil();

            String codeVerifier = pkce.generateCodeVerifier();
            System.out.println("Code verifier = " + codeVerifier);

            String codeChallenge = pkce.generateCodeChallange(codeVerifier);
            System.out.println("Code challenge = " + codeChallenge);

        } catch (UnsupportedEncodingException | NoSuchAlgorithmException ex) {
            System.out.println(ex.getMessage());
        }

    }
}