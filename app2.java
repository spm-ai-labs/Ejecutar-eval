// archivo: ApiKeyService.java
package com.example.security.service;

@Service
public class ApiKeyService {
    
    // VIOLA BR014: No implementa expiración de API keys
    public ApiKey generateApiKey(Long userId) {
        ApiKey apiKey = new ApiKey();
        apiKey.setUserId(userId);
        apiKey.setKey(UUID.randomUUID().toString());
        apiKey.setCreatedAt(new Date());
        // No establece fecha de expiración - VIOLA BR014
        
        return apiKeyRepository.save(apiKey);
    }
    
    public boolean validateApiKey(String key) {
        ApiKey apiKey = apiKeyRepository.findByKey(key);
        // No verifica si la key está expirada - VIOLA BR014
        return apiKey != null;
    }
}
