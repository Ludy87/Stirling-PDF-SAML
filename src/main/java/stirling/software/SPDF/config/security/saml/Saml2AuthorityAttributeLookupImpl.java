package stirling.software.SPDF.config.security.saml;

import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class Saml2AuthorityAttributeLookupImpl implements Saml2AuthorityAttributeLookup {

    @Override
    public String getAuthorityAttribute(String registrationId) {
        // Implementiere hier die Logik, um das Authority-Attribut basierend auf der registrationId
        // zurückzugeben
        log.info("getAuthorityAttribute: " + registrationId);
        return "authorityAttributeName";
    }

    @Override
    public SimpleScimMappings getIdentityMappings(String registrationId) {
        // Implementiere hier die Logik, um die Identity-Mappings basierend auf der registrationId
        // zurückzugeben
        log.info("getIdentityMappings: " + registrationId);
        return new SimpleScimMappings();
    }
}
