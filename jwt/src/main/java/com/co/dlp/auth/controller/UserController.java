package com.co.dlp.auth.controller;

import com.co.dlp.auth.jwt.utils.JwtUtils;
import com.co.dlp.auth.model.User;
import com.co.dlp.auth.model.UserResponse;
import com.co.dlp.auth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.coyote.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

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
    private JwtUtils jwtUtils;


    @Autowired
    public UserController(UserService userService, AuthenticationManager authenticationManager){
        this.userService = userService;
        this.authenticationManager = authenticationManager;
    }


    @PostMapping("/signing")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest){
        Authentication authentication;

        try{
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );

        }catch(AuthenticationException e){
            Map<String, Object> map = new HashMap<>();
            map.put(MESSAGE, "Invalid credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        User user = (User) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUsername(user);

        LoginResponse response =
                new LoginResponse(user.getUsername(), jwtToken);

        return ResponseEntity.ok(response);
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

            HttpSession session = request.getSession(true);
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
            log.info("Session created: ID={}", session.getId());
            log.info("Authentication successful for user: {}, authorities: {}",
                    username, authentication.getAuthorities());

            return ResponseEntity.ok().body("Login successful, session ID: " + session.getId());

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
                    new UserResponse("User registered " + registered.getUsername()));
        }catch(Exception e){
            return ResponseEntity.badRequest().body(new UserResponse(e.getMessage()));
        }
    }

    @GetMapping("/check-session")
    public ResponseEntity<?> checkSession(HttpSession session){
        log.info("Checking session. ID: {}", session.getId());
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        log.info("Session ID: {}",session.getId());
        log.info("Session Creation Time: {}",session.getCreationTime());
        log.info("Session Max Inactive Interval: {}",session.getMaxInactiveInterval());

        if (auth == null || !auth.isAuthenticated() || auth.getPrincipal().equals("anonymousUser")) {
            log.warn("Unauthorized session check attempt.");
            return ResponseEntity.status(403).body("Session is invalid or expired");
        }

        long sessionExpiryTime = session.getLastAccessedTime() + (session.getMaxInactiveInterval() * 1000L);
        return ResponseEntity.ok("Session active for user: " + auth.getName() + ". Expires at: " + sessionExpiryTime);
    }

    @GetMapping("/dashboard")
    public String dashboard(){

        return "The Dashboard";
    }

}
