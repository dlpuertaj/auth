package com.co.dlp.auth.model;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class UserResponse {
    private String message;

    public UserResponse(String message){
        this.message = message;
    }
}
