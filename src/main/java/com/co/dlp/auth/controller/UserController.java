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
    public static final String MESSAGE = "message";

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
    public ResponseEntity<UserResponse> login(@RequestBody Map<String, String> requestBody , HttpServletRequest request) {
        String username = requestBody.get("username");
        String password = requestBody.get("password");


        boolean isAuthenticated = userService.authenticate(username, password);

        if(isAuthenticated){
            HttpSession session = request.getSession();
            session.setAttribute("username", username);
            return ResponseEntity.ok().body(new UserResponse(true, "Login successful"));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new UserResponse(false, "Invalid credentials"));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response){
        HttpSession session = request.getSession(false);

        if (session != null)
            session.invalidate();

        return ResponseEntity.ok().body(Map.of(MESSAGE, "Logged out"));
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(Authentication authentication){
        if (authentication != null)
            return ResponseEntity.ok().body(Map.of("user",authentication.getName()));

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(MESSAGE, "Not authenticated"));    }

}
