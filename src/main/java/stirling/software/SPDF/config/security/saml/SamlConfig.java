package stirling.software.SPDF.config.security.saml;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.core.Saml2X509Credential.Saml2X509CredentialType;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.FileCopyUtils;

import lombok.extern.slf4j.Slf4j;
import stirling.software.SPDF.model.ApplicationProperties;

@Configuration
@Slf4j
public class SamlConfig {

    @Autowired ApplicationProperties applicationProperties;

    @Bean
    @ConditionalOnProperty(
            value = "security.saml.enabled",
            havingValue = "true",
            matchIfMissing = false)
    public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository()
            throws Exception {
        log.info(applicationProperties.getSecurity().getSAML().getIdpMetadataLocation());
        log.info(applicationProperties.getSecurity().getSAML().getEntityId());
        log.info(applicationProperties.getSecurity().getSAML().getRegistrationId());

        // Laden des privaten Schlüssels
        Resource privateKeyResource = new ClassPathResource("saml-private-key.pem");
        String privateKey =
                new String(
                        FileCopyUtils.copyToByteArray(privateKeyResource.getInputStream()),
                        StandardCharsets.UTF_8);

        // Laden des öffentlichen Zertifikats
        Resource certificateResource = new ClassPathResource("saml-public-certificate.crt");
        String certificate =
                new String(
                        FileCopyUtils.copyToByteArray(certificateResource.getInputStream()),
                        StandardCharsets.UTF_8);

        Saml2X509Credential signingCredential =
                new Saml2X509Credential(
                        readPrivateKey(privateKey),
                        readCertificate(certificate),
                        Saml2X509CredentialType.SIGNING);

        // Keycloak
        Resource keycloakCertificateResource =
                new ClassPathResource("saml-public-certificate-keycloak.crt");
        String keycloakCertificate =
                new String(
                        FileCopyUtils.copyToByteArray(keycloakCertificateResource.getInputStream()),
                        StandardCharsets.UTF_8);

        X509Certificate verificationCertificate = readCertificate(keycloakCertificate);

        Saml2X509Credential verificationCredential =
                new Saml2X509Credential(
                        verificationCertificate,
                        Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);

        // Okta
        Resource certificateResourceOkta = new ClassPathResource("okta.cert");
        String certificateOkta =
                new String(
                        FileCopyUtils.copyToByteArray(certificateResourceOkta.getInputStream()),
                        StandardCharsets.UTF_8);
        X509Certificate verificationCertificateOkta = readCertificate(certificateOkta);

        Saml2X509Credential verificationCredentialOkta =
                new Saml2X509Credential(
                        verificationCertificateOkta,
                        Saml2X509Credential.Saml2X509CredentialType.VERIFICATION);

        RelyingPartyRegistration registration =
                RelyingPartyRegistrations.fromMetadataLocation(
                                applicationProperties
                                        .getSecurity()
                                        .getSAML()
                                        .getIdpMetadataLocation())
                        .entityId(applicationProperties.getSecurity().getSAML().getEntityId())
                        .registrationId(
                                applicationProperties.getSecurity().getSAML().getRegistrationId())
                        // Cert
                        // .signingX509Credentials((credentials) ->
                        // credentials.add(signingCredential))
                        .assertionConsumerServiceLocation(
                                "http://localhost:8080/login/saml2/sso/"
                                        + applicationProperties
                                                .getSecurity()
                                                .getSAML()
                                                .getRegistrationId())
                        // Konfiguration des Single Logout
                        .singleLogoutServiceLocation("http://localhost:8080/logout/saml2/slo")
                        // .singleLogoutServiceResponseLocation(
                        //         "http://localhost:8080/logout/saml2/slo")
                        .singleLogoutServiceBinding(
                                Saml2MessageBinding.POST) // Oder REDIRECT, je nach Bedarf
                        // .assertingPartyDetails(
                        //         party ->
                        //                 party.entityId(
                        //                         applicationProperties
                        //                                 .getSecurity()
                        //                                 .getSAML()
                        //                                 .getIdpMetadataLocation())
                        // .verificationX509Credentials(
                        //         c -> c.add(verificationCredentialOkta))
                        // .wantAuthnRequestsSigned(true))
                        //         party ->
                        //
                        // party.entityId("http://192.168.0.220:8089/realms/master")
                        //                         .singleLogoutServiceBinding(
                        //                                 Saml2MessageBinding.POST)
                        //                         .wantAuthnRequestsSigned(false)
                        //                         .verificationX509Credentials(
                        //                                 c ->
                        // c.add(verificationCredential)))
                        // )
                        .build();
        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

    private RSAPrivateKey readPrivateKey(String key) throws Exception {
        String privateKeyContent =
                key.replace("-----BEGIN PRIVATE KEY-----", "")
                        .replace("-----END PRIVATE KEY-----", "")
                        .replaceAll("\\R", "")
                        .replaceAll("\\r\\n", "")
                        .replaceAll("\\r", "")
                        .replaceAll("\\n", "")
                        .replaceAll("\\s+", "");
        log.info(privateKeyContent);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        byte[] decodedKey = Base64.getDecoder().decode(privateKeyContent);
        return (RSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));
    }

    private X509Certificate readCertificate(String cert) throws Exception {
        String certContent =
                cert.replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("-----END CERTIFICATE-----", "")
                        .replaceAll("\\R", "")
                        .replaceAll("\\r\\n", "")
                        .replaceAll("\\r", "")
                        .replaceAll("\\n", "")
                        .replaceAll("\\s+", "");
        log.info(certContent);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        byte[] decodedCert = Base64.getDecoder().decode(certContent);
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decodedCert));
    }
}
