package com.co.dlp.auth.controller;

import com.co.dlp.auth.model.User;
import com.co.dlp.auth.model.UserResponse;
import com.co.dlp.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

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
                    new UserResponse(true,"User registered", registered));
        }catch(Exception e){
            return ResponseEntity.badRequest().body(new UserResponse(false, e.getMessage()));
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if(session != null)
            return ResponseEntity.ok().body(Map.of("message", "Login successful"));

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message","Login Failed"));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response){
        HttpSession session = request.getSession(false);

        if (session != null)
            session.invalidate();

        return ResponseEntity.ok().body(Map.of("message", "Logged out"));
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(Authentication authentication){
        if (authentication != null)
            return ResponseEntity.ok().body(Map.of("user",authentication.getName()));

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("message", "Not authenticated"));    }

}
