package com.example.demo;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

// Vulnerable fixture: the controller binds @RequestBody directly to the
// User entity (R-01) with no @Valid annotation (R-04).
@RestController
public class UserController {

    @PostMapping("/users")
    public User createUser(@RequestBody User user) {
        return user;
    }
}
