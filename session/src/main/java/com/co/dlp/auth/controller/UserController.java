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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserController {

    private static final Logger log = LoggerFactory.getLogger(UserController.class);
    public static final String MESSAGE = "message";
    public static final String USERNAME = "username";
    public static final String PASSWORD = "password";


    private final UserService userService;
    private final AuthenticationManager authenticationManager;


    @Autowired
    public UserController(UserService userService, AuthenticationManager authenticationManager){
        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(HttpServletRequest request, @RequestBody Map<String, String> requestBody){
        String username = requestBody.get(USERNAME);
        String password = requestBody.get(PASSWORD);
        log.info("Logging in user: {}", username);

        try{

            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password)
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.info("Authentication successful for user: {}, authorities: {}",
                    username, authentication.getAuthorities());

            request.getSession(true);

            return ResponseEntity.ok().build();

        }catch(Exception e){
            log.error("Error logging in user: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new UserResponse("Invalid credentials"));
        }
        
    }

    @CrossOrigin(origins = "http://localhost:3000")
    @PostMapping("/register")
    public ResponseEntity<UserResponse> registerUser(@RequestBody Map<String, String> requestBody) throws Exception {
        String username = requestBody.get(USERNAME);
        String password = requestBody.get(PASSWORD);
        log.info("Registering user: {}", username);

        boolean isAuthenticated = userService.authenticate(username, password);

        if(isAuthenticated){
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(new UserResponse("Username already registered"));
        }

        try{

            User registered = userService.registerUser(username, password);
            return ResponseEntity.ok(
                    new UserResponse("User registered"));
        }catch(Exception e){
            return ResponseEntity.badRequest().body(new UserResponse(e.getMessage()));
        }
    }

    @GetMapping("/check-session")
    public ResponseEntity<String> checkSession(){
        log.info("Checking session");
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())){
            log.info("Session is Active");
            return ResponseEntity.ok("Session is active");
        } else {
            log.info("Session is not active");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Session is not active");
        }
    }

    @GetMapping("/test-session")
    public ResponseEntity<String> testSession() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("Test session - Auth: {}, Principal: {}", auth, auth != null ? auth.getPrincipal() : "null");

        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            log.info("Session is Active");
            return ResponseEntity.ok("Session active for: " + auth.getName());
        } else {
            log.info("Session is not active");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No active session");
        }
    }

    @GetMapping("/dashboard")
    public ResponseEntity<String> dashboard(){

        String username = SecurityContextHolder.getContext().getAuthentication().getName();

        return ResponseEntity.ok("Welcome, " + username + "!");
    }

}
