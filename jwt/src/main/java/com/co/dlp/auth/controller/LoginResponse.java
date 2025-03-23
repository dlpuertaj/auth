package com.co.dlp.auth.controller;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
public class LoginResponse {

    private String jwtToken;

    private String username;

    public LoginResponse(String username, String jwtToken) {
        this.jwtToken = jwtToken;
        this.username = username;
    }

}
