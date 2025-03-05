package com.co.dlp.auth.model;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class UserResponse {
    private boolean success;
    private String message;
    private Object data;

    public UserResponse(boolean success, String message){
        this.success = success;
        this.message = message;
    }

    public UserResponse(boolean success, String message, Object data){
        this.success = success;
        this.message = message;
        this.data = data;
    }

}
