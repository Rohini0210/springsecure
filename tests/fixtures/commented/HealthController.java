package com.example.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// Regression fixture for parser Defect 1: the @RequestBody line below is
// commented out, so it must produce no finding. Before the comment-stripping
// fix it produced a spurious R-01 and a spurious R-04 finding.
@RestController
public class HealthController {

    // @RequestBody User user
    // The endpoint above used to bind a User directly; it is now disabled.
    @GetMapping("/health")
    public String health() {
        return "ok";
    }
}
