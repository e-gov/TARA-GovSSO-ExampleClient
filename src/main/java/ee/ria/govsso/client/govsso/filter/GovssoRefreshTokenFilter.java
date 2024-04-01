package ee.ria.govsso.client.govsso.filter;

import com.nimbusds.jose.util.JSONObjectUtils;
import ee.ria.govsso.client.govsso.configuration.GovssoRefreshTokenTokenResponseClient;
import ee.ria.govsso.client.govsso.configuration.authentication.GovssoAuthentication;
import ee.ria.govsso.client.govsso.configuration.authentication.GovssoExampleClientUserFactory;
import ee.ria.govsso.client.govsso.oauth2.GovssoSessionUtil;
import ee.ria.govsso.client.util.AccessTokenUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import static ee.ria.govsso.client.govsso.configuration.GovssoOidcConfiguration.GOVSSO_REGISTRATION_ID;
import static org.springframework.http.HttpMethod.POST;

/**
 * An {@link GovssoRefreshTokenFilter} responsible for initiating OAuth 2.0 Refresh Token Grant request
 * and updating authenticated principal.
 */
@Slf4j
@RequiredArgsConstructor
@Builder
public class GovssoRefreshTokenFilter extends OncePerRequestFilter {

    public static final RequestMatcher REQUEST_MATCHER =
            new AntPathRequestMatcher("/oauth2/refresh/" + GOVSSO_REGISTRATION_ID, POST.name());

    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;
    private final GovssoRefreshTokenTokenResponseClient refreshTokenResponseClient;
    private final JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory;
    private final OAuth2UserService<OidcUserRequest, OidcUser> userService;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final GovssoExampleClientUserFactory govssoExampleClientUserFactory;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        RequestMatcher.MatchResult result = REQUEST_MATCHER.matcher(request);
        if (!result.isMatch()) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            handleRefresh(response, request.getParameter("scope"));
        } catch (Exception e) {
            log.error("Refresh token request failed", e);
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
    }

    private void handleRefresh(HttpServletResponse response, String scope) throws IOException {
        Authentication previousAuthentication =
                SecurityContextHolder.getContext().getAuthentication();
        if (!(previousAuthentication instanceof GovssoAuthentication previousGovssoAuthentication)) {
            throw new IllegalArgumentException(
                    "GovSSO session update not supported for given authentication, " +
                            "unsupported authentication type");
        }
        String tokenRegistrationId = previousGovssoAuthentication.getAuthorizedClientRegistrationId();
        if (!Objects.equals(GOVSSO_REGISTRATION_ID, tokenRegistrationId)) {
            throw new IllegalArgumentException(
                    "GovSSO session update not supported for given authentication, " +
                            "unsupported client registration ID \"" + tokenRegistrationId + "\"");
        }
        ClientRegistration clientRegistration =
                clientRegistrationRepository.findByRegistrationId(GOVSSO_REGISTRATION_ID);
        OAuth2AccessTokenResponse tokenResponse =
                performRefreshTokenGrantRequest(clientRegistration, previousGovssoAuthentication.getRefreshToken(), scope);
        GovssoAuthentication newAuthToken =
                createNewAuthentication(clientRegistration, tokenResponse);
        SecurityContextHolder.getContext().setAuthentication(newAuthToken);
        saveAuthorizedClient(newAuthToken, clientRegistration, tokenResponse);

        writeResponse(response, ((OidcUser) newAuthToken.getPrincipal()).getIdToken(), tokenResponse.getAccessToken().getTokenValue(), tokenResponse.getRefreshToken().getTokenValue());
        log.info("Refresh token request successful");
    }

    private GovssoAuthentication createNewAuthentication(
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
        return new GovssoAuthentication(
                oidcUser,
                oidcUser.getAuthorities(),
                oidcUserRequest.getClientRegistration().getRegistrationId(),
                tokenResponse.getRefreshToken(),
                tokenResponse.getAccessToken(),
                govssoExampleClientUserFactory.create(oidcUser));
    }

    private void writeResponse(HttpServletResponse response, OidcIdToken idToken, String accessToken, String refreshToken) throws IOException {
        String refreshTokenResponse = generateDemoResponse(idToken, accessToken, refreshToken);
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.displayName());
        PrintWriter writer = response.getWriter();
        writer.write(refreshTokenResponse);
    }

    private OAuth2AccessTokenResponse performRefreshTokenGrantRequest(
            ClientRegistration clientRegistration,
            OAuth2RefreshToken refreshToken,
            String scope) {
        GovssoRefreshTokenTokenResponseClient.Request tokenRequest = new GovssoRefreshTokenTokenResponseClient.Request(
                clientRegistration,
                refreshToken,
                scope);
        return refreshTokenResponseClient.getTokenResponse(tokenRequest);
    }

    /* Since we are using `NoopAuthorizedClientService`, this method does not actually do anything, but is still kept
     * for reference.
     */
    private void saveAuthorizedClient(GovssoAuthentication authToken, ClientRegistration clientRegistration,
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
    private String generateDemoResponse(OidcIdToken idToken, String accessToken, String refreshToken) {
        Map<String, Object> response = new HashMap<>();
        response.put("id_token", idToken.getTokenValue());

        if (AccessTokenUtil.isJwtAccessToken(accessToken)) {
            response.put("access_token", accessToken);
        }
        response.put("refresh_token", refreshToken);
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
        response.put("time_until_govsso_session_expiration_in_seconds",
                GovssoSessionUtil.getTimeUntilAuthenticationExpiration().toSeconds());
        return JSONObjectUtils.toJSONString(response);
    }

}
