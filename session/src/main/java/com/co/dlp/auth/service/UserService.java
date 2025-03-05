package com.co.dlp.auth.service;

import com.co.dlp.auth.model.User;
import com.co.dlp.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User registerUser(String username, String password) throws Exception {

        if(userRepository.findByUsername(username).isPresent()){
            throw new Exception("Username already exist");
        }
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        return userRepository.save(user);
    }

    public boolean authenticate(String username, String password){
        User user = userRepository.findByUsername(username)
                                  .orElse(null);
        if(user == null){
            return false;
        }
        return passwordEncoder.matches(password, user.getPassword());
    }

}
