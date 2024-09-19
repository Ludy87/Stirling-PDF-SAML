package stirling.software.SPDF.config.security.saml;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import stirling.software.SPDF.model.ApplicationProperties;

@Slf4j
public class Saml2LogoutSuccessHandler extends SimpleUrlLogoutSuccessHandler {

    private final ApplicationProperties applicationProperties;
    private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

    public Saml2LogoutSuccessHandler(
            ApplicationProperties applicationProperties,
            RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
        this.applicationProperties = applicationProperties;
        this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
    }

    @Override
    public void onLogoutSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {

        RelyingPartyRegistration relyingPartyRegistration =
                relyingPartyRegistrationRepository.findByRegistrationId(
                        applicationProperties.getSecurity().getSAML().getRegistrationId());

        log.info(relyingPartyRegistration.getSingleLogoutServiceLocation());

        String redirectUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            log.debug("Response has already been committed. Unable to redirect to " + redirectUrl);
            return;
        }

        response.sendRedirect(relyingPartyRegistration.getSingleLogoutServiceLocation());

        // getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }

    protected String determineTargetUrl(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication) {
        // Default to the root URL
        return "/";
    }
}
