package com.co.dlp.auth.model;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class UserResponse {
    private boolean success;
    private String message;
    private String username;

    public UserResponse(boolean success, String message){
        this.success = success;
        this.message = message;
    }

    public UserResponse(boolean success, String message, String username){
        this.success = success;
        this.message = message;
        this.username = username;
    }

}
