package org.eclipse.openvsx.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class PropertyReader {

    private static final Logger log = LoggerFactory.getLogger(PropertyReader.class);
    private final Environment environment;

    @Autowired
    public PropertyReader(Environment environment) {
        this.environment = environment;
    }

    public String getProperty(String propertyName) {
        return environment.getProperty(propertyName);
    }

    public Optional<String> getUserAttribute(String provider, String alias, OAuth2User oauth2User) {
        var property = "spring.security.oauth2.client.registration." + provider + ".attributes." + alias;
        log.debug("Looking up property {}", property);
        var attribute = getProperty(property);
        if (attribute == null) {
            return Optional.empty();
        }
        log.debug("Found attribute {}", attribute);
        String value = oauth2User.getAttribute(attribute);
        log.debug("Result: {} = {}", attribute, value);
        return Optional.ofNullable(value);
    }
}
