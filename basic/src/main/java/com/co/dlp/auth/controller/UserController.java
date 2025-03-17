package com.co.dlp.auth.controller;

import com.co.dlp.auth.model.User;
import com.co.dlp.auth.model.UserResponse;
import com.co.dlp.auth.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {

    private static final Logger log = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<UserResponse> registerUser(@RequestParam String username, @RequestParam String password) throws Exception {
        log.info("Registering user: {}", username);
        try{
            User registered = userService.registerUser(username, password);
            return ResponseEntity.ok(
                    new UserResponse(true,"User registered", registered.getUsername()));
        }catch(Exception e){
            return ResponseEntity.badRequest().body(new UserResponse(false, e.getMessage()));
        }
    }

    @GetMapping("/protected-resource")
    public ResponseEntity<String> protectedResource() {
        return ResponseEntity.ok("You are authenticated!");
    }

}
