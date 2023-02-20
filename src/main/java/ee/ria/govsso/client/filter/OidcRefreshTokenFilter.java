package ee.ria.govsso.client.filter;

import com.nimbusds.jose.util.JSONObjectUtils;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.client.RestOperations;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;
import static org.springframework.http.HttpMethod.POST;

/**
 * An {@link OidcRefreshTokenFilter} responsible for initiating OAuth 2.0 Refresh Token Grant request
 * and updating authenticated principal.
 */
@Slf4j
public class OidcRefreshTokenFilter extends OncePerRequestFilter {

    public static final RequestMatcher REQUEST_MATCHER =
            new AntPathRequestMatcher("/oauth2/refresh/{registrationId}", POST.name());

    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;
    private final DefaultRefreshTokenTokenResponseClient refreshTokenResponseClient;
    private final JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory;
    private final OAuth2UserService<OidcUserRequest, OidcUser> userService;

    @Builder
    public OidcRefreshTokenFilter(
            OAuth2AuthorizedClientService oAuth2AuthorizedClientService,
            @Qualifier("govssoRestTemplate") RestOperations restOperations,
            JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory,
            OAuth2UserService<OidcUserRequest, OidcUser> userService) {
        this.oAuth2AuthorizedClientService = oAuth2AuthorizedClientService;
        this.refreshTokenResponseClient = new DefaultRefreshTokenTokenResponseClient();
        this.refreshTokenResponseClient.setRestOperations(restOperations);
        this.idTokenDecoderFactory = idTokenDecoderFactory;
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        RequestMatcher.MatchResult result = REQUEST_MATCHER.matcher(request);
        if (!result.isMatch()) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            handleRefresh(response, result.getVariables().get("registrationId"));
        } catch (Exception e) {
            log.error("Refresh token request failed", e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
    }

    private void handleRefresh(HttpServletResponse response, String registrationId) throws IOException {
        OAuth2AuthenticationToken previousAuthenticationToken =
                (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        String tokenRegistrationId = previousAuthenticationToken.getAuthorizedClientRegistrationId();
        if (!Objects.equals(registrationId, tokenRegistrationId)) {
            throw new RuntimeException(
                    "Registration ID mismatch: " +
                            "authorized client registration ID: \"" + tokenRegistrationId + "\", " +
                            "provided client registration ID: \"" + registrationId + "\"");
        }
        OAuth2AuthorizedClient client = oAuth2AuthorizedClientService.loadAuthorizedClient(
                tokenRegistrationId, previousAuthenticationToken.getName());
        ClientRegistration clientRegistration = client.getClientRegistration();
        OAuth2AccessTokenResponse tokenResponse = performRefreshTokenGrantRequest(client);
        OAuth2AuthenticationToken newAuthToken = createNewAuthentication(clientRegistration, tokenResponse);
        SecurityContextHolder.getContext().setAuthentication(newAuthToken);
        saveAuthorizedClient(newAuthToken, clientRegistration, tokenResponse);

        writeResponse(response, ((OidcUser) newAuthToken.getPrincipal()).getIdToken());
        log.info("Refresh token request successful");
    }

    private OAuth2AuthenticationToken createNewAuthentication(
            ClientRegistration clientRegistration, OAuth2AccessTokenResponse tokenResponse) {
        String idToken = (String) tokenResponse.getAdditionalParameters().get("id_token");
        Jwt validatedIdToken = idTokenDecoderFactory.createDecoder(clientRegistration).decode(idToken);
        OidcIdToken oidcIdToken = new OidcIdToken(
                validatedIdToken.getTokenValue(), validatedIdToken.getIssuedAt(),
                validatedIdToken.getExpiresAt(), validatedIdToken.getClaims());
        OidcUserRequest oidcUserRequest = new OidcUserRequest(
                clientRegistration, tokenResponse.getAccessToken(), oidcIdToken,
                tokenResponse.getAdditionalParameters());
        OidcUser oidcUser = this.userService.loadUser(oidcUserRequest);
        return new OAuth2AuthenticationToken(
                oidcUser, oidcUser.getAuthorities(), oidcUserRequest.getClientRegistration().getRegistrationId());
    }

    private void writeResponse(HttpServletResponse response, OidcIdToken idToken) throws IOException {
        String refreshTokenResponse = generateDemoResponse(idToken);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        PrintWriter writer = response.getWriter();
        writer.write(refreshTokenResponse);
    }

    private OAuth2AccessTokenResponse performRefreshTokenGrantRequest(OAuth2AuthorizedClient client) {
        ClientRegistration clientRegistration = client.getClientRegistration();
        OAuth2RefreshTokenGrantRequest tokenRequest = new OAuth2RefreshTokenGrantRequest(
                clientRegistration,
                client.getAccessToken(),
                requireNonNull(client.getRefreshToken()));
        return refreshTokenResponseClient.getTokenResponse(tokenRequest);
    }

    private void saveAuthorizedClient(OAuth2AuthenticationToken authToken, ClientRegistration clientRegistration,
                                      OAuth2AccessTokenResponse tokenResponse) {
        OAuth2AuthorizedClient updatedClient = new OAuth2AuthorizedClient(
                clientRegistration, authToken.getName(), tokenResponse.getAccessToken(),
                tokenResponse.getRefreshToken());
        oAuth2AuthorizedClientService.saveAuthorizedClient(updatedClient, authToken);
    }

    /**
     * You most likely wouldn't want to return all of this to your applications front-end but since we do want to
     * display all of it in example client to make debugging easier, we are doing it in this case.
     */
    private String generateDemoResponse(OidcIdToken idToken) {
        Map<String, Object> response = new HashMap<>();
        response.put("id_token", idToken.getTokenValue());
        response.put("jti", idToken.getClaimAsString("jti"));
        response.put("iss", idToken.getIssuer().toString());
        response.put("aud", idToken.getAudience().stream()
                .map(String::valueOf)
                .collect(Collectors.joining(",", "[", "]")));
        response.put("exp", idToken.getClaimAsString("exp"));
        response.put("iat", idToken.getClaimAsString("iat"));
        response.put("sub", idToken.getSubject());
        response.put("birthdate", idToken.getClaimAsString("birthdate"));
        response.put("given_name", idToken.getClaimAsString("given_name"));
        response.put("family_name", idToken.getClaimAsString("family_name"));
        response.put("amr", idToken.getClaimAsString("amr"));
        response.put("nonce", idToken.getClaimAsString("nonce"));
        response.put("acr", idToken.getClaimAsString("acr"));
        response.put("at_hash", idToken.getClaimAsString("at_hash"));
        response.put("sid", idToken.getClaimAsString("sid"));
        return JSONObjectUtils.toJSONString(response);
    }

}
