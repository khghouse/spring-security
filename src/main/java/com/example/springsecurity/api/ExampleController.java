package com.example.springsecurity.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExampleController {

    @PostMapping("/example")
    public ResponseEntity postExample() {
        return ResponseEntity.ok("example");
    }

    @GetMapping("/user")
    public ResponseEntity getUser() {
        return ResponseEntity.ok("user");
    }

    @GetMapping("/admin")
    public ResponseEntity getAdmin() {
        return ResponseEntity.ok("admin");
    }

}
