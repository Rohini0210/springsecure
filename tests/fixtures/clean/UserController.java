package com.example.demo;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import jakarta.validation.Valid;

// Clean fixture: the controller binds @RequestBody to a DTO-style request
// object (not an entity name) and validates it. No findings expected.
// Note: the request type is deliberately NOT named *User* — the detector
// matches entity names by substring, so a type such as UserDto would still
// trigger R-01.
@RestController
public class UserController {

    @PostMapping("/users")
    public void createUser(@Valid @RequestBody SignupRequest request) {
    }
}
