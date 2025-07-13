// DebugController.java - VIOLA ESPECÍFICAMENTE CR-SEC-010
package com.example.api.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;

@RestController
@RequestMapping("/api")
@Profile("production") // Activo en producción - VIOLA CR-SEC-010
@ConditionalOnProperty(name = "debug.mode.enabled", havingValue = "true")
public class DebugController {
    
    // Endpoint de debug activo en producción
    @GetMapping("/debug/heap")
    public Map<String, Long> getHeapInfo() {
        Runtime runtime = Runtime.getRuntime();
        Map<String, Long> heap = new HashMap<>();
        heap.put("maxMemory", runtime.maxMemory());
        heap.put("totalMemory", runtime.totalMemory());
        heap.put("freeMemory", runtime.freeMemory());
        return heap;
    }
    
    // Logger con nivel DEBUG en producción
    private static final Logger logger = LoggerFactory.getLogger(DebugController.class);
    
    @PostMapping("/users")
    public ResponseEntity<String> createUser(@RequestBody User user) {
        // Logging excesivo en producción - VIOLA CR-SEC-010
        logger.debug("Creating user with data: {}", user.toString());
        logger.debug("Password hash: {}", user.getPasswordHash());
        logger.debug("Full request details: {}", request.toString());
        
        userService.save(user);
        
        // Respuesta genérica - NO viola CR-SEC-016
        return ResponseEntity.ok("User created successfully");
    }
}
