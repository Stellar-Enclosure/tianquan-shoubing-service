package top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import top.egon.cola.component.common.crypto.digest.Digests;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.controller.filter.TenantLoginAuthenticationFilter;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.OAuthInteractionBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.bo.TrustedRealmBO;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.domain.enums.OAuthClientPurposeEnum;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthClientRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthInteractionRepository;
import top.egon.cola.platform.tianquan.shoubing.admin.oauth.service.TenantIssuerService;
import top.egon.cola.platform.tianquan.shoubing.admin.token.service.impl.OAuthPayloadCipherComponent;
import top.egon.cola.platform.tianquan.shoubing.core.oauth.OAuthClient;

/** SAS RequestCache/CSRF adapters backed by a bounded SQL interaction and separate browser secrets. */
@Component("oauthBrowserInteractionComponent")
@RequiredArgsConstructor
public class OAuthBrowserInteractionComponent implements RequestCache, CsrfTokenRepository {
    public static final String INTERACTION_ATTRIBUTE = OAuthBrowserInteractionComponent.class.getName() + ".interaction";
    private static final String BINDING_COOKIE = "__Host-idp-binding";
    private static final Set<String> LIVE = Set.of("PENDING", "AUTHENTICATED", "CONSENT_REQUIRED");
    private static final Set<String> AUTHORIZATION_PARAMETERS = Set.of("client_id", "response_type", "redirect_uri", "scope",
            "resource", "state", "nonce", "code_challenge", "code_challenge_method", "prompt", "max_age", "browser_binding");
    @Qualifier("oAuthInteractionRepository") private final OAuthInteractionRepository interactions;
    @Qualifier("oAuthClientRepository") private final OAuthClientRepository clients;
    @Qualifier("oAuthRealmRepository") private final top.egon.cola.platform.tianquan.shoubing.admin.oauth.repository.OAuthRealmRepository realms;
    @Qualifier("tenantIssuerService") private final TenantIssuerService issuers;
    @Qualifier("oauthPayloadCipherComponent") private final OAuthPayloadCipherComponent cipher;
    @Qualifier("oauthAuthenticationJwtService") private final OAuthAuthenticationJwtService authenticationJwts;
    @Qualifier("identityFacade") private final top.egon.cola.platform.tianquan.shoubing.core.identity.IdentityFacade identities;
    @Qualifier("oauthSsoLifecycleService") private final OAuthSsoLifecycleService sso;
    @Qualifier("jacksonObjectMapper") private final ObjectMapper mapper;
    @Qualifier("idpClock") private final Clock clock;
    @Value("${egon.tianquan-shoubing.oauth.public-origin}") private final URI publicOrigin;
    private final SecureRandom random = new SecureRandom();

    /** The redirect target is checked against an active registered client before any request is saved. */
    @Override
    @Transactional
    public void saveRequest(HttpServletRequest request, HttpServletResponse response) {
        if (!"GET".equals(request.getMethod()) || !request.getRequestURI().matches("/tenants/[1-9][0-9]{0,18}/oauth2/authorize")) {
            return;
        }
        TrustedRealmBO realm = realm(request);
        if (!request.getRequestURI().equals(realm.getIssuer().getRawPath() + "/oauth2/authorize")) {
            return;
        }
        Map<String, String[]> parameters = request.getParameterMap();
        if (!AUTHORIZATION_PARAMETERS.containsAll(parameters.keySet()) || request.getQueryString() != null && request.getQueryString().length() > 16_384
                || !parameters.keySet().containsAll(Set.of("client_id", "response_type", "redirect_uri", "scope", "resource", "state", "nonce", "code_challenge", "code_challenge_method"))
                || parameters.values().stream().anyMatch(value -> value == null || value.length != 1 || value[0] == null)
                || !"code".equals(request.getParameter("response_type")) || !"S256".equals(request.getParameter("code_challenge_method"))
                || request.getParameter("state") == null || request.getParameter("state").length() < 32 || request.getParameter("state").length() > 512
                || request.getParameter("nonce") == null || request.getParameter("nonce").length() < 32 || request.getParameter("nonce").length() > 512
                || request.getParameter("code_challenge") == null || !request.getParameter("code_challenge").matches("[A-Za-z0-9_-]{43}")) {
            throw rejected();
        }
        for (var entry : parameters.entrySet()) {
            int maximum = switch (entry.getKey()) {
                case "scope" -> 8320;
                case "redirect_uri", "resource" -> 2048;
                case "state", "nonce" -> 512;
                default -> 128;
            };
            if (entry.getValue()[0].isBlank() || entry.getValue()[0].length() > maximum) { throw rejected(); }
        }
        var client = clients.findByClientId(realm, request.getParameter("client_id"))
                .filter(value -> value.getStatus() == OAuthClient.Status.ACTIVE && value.getPurpose() == OAuthClientPurposeEnum.USER)
                .orElseThrow(OAuthBrowserInteractionComponent::rejected);
        var scopes = Arrays.asList(Objects.requireNonNullElse(request.getParameter("scope"), "").split(" ", -1));
        if (!client.getRedirectUris().contains(request.getParameter("redirect_uri")) || !client.getResourceUris().contains(request.getParameter("resource"))
                || scopes.isEmpty() || scopes.size() > 64 || scopes.stream().anyMatch(value -> !value.matches("[A-Za-z0-9:._-]{1,128}"))
                || Set.copyOf(scopes).size() != scopes.size() || !client.getAllowedScopes().containsAll(scopes)) { throw rejected(); }
        String edgeBinding = request.getParameter("browser_binding");
        if (client.isBrowserBound() && (edgeBinding == null || !edgeBinding.matches("[0-9a-f]{64}"))
                || !client.isBrowserBound() && edgeBinding != null) { throw rejected(); }
        String digest = TenantLoginAuthenticationFilter.authorizationRequestDigest(realm.getIssuer(), parameters);
        String previous = cookie(request, name("interaction", realm));
        if (previous != null) {
            var current = interactions.findByInteractionId(realm, previous).orElse(null);
            if (current != null && "AUTHORIZATION".equals(current.getPurpose()) && LIVE.contains(current.getState()) && current.getExpiresAt().isAfter(clock.instant())
                    && current.getRequestDigest().equals(digest) && current.getBrowserBindingDigest().equals(bindingDigest(request))) {
                request.setAttribute(INTERACTION_ATTRIBUTE, current);
                return;
            }
        }
        String binding = cookie(request, BINDING_COOKIE);
        if (binding == null) { binding = secret(); setCookie(request, response, BINDING_COOKIE, binding, Duration.ofHours(8)); }
        CsrfToken csrf = loadToken(request);
        if (csrf == null) { csrf = generateToken(request); saveToken(csrf, request, response); }
        String interactionId = secret();
        String json;
        try { json = mapper.writeValueAsString(parameters); }
        catch (com.fasterxml.jackson.core.JsonProcessingException invalid) { throw new IllegalStateException("OAUTH_INTERACTION_ENCODING_FAILED", invalid); }
        var interaction = OAuthInteractionBO.builder().interactionId(interactionId).purpose("AUTHORIZATION")
                .clientPk(client.getId()).resourceUri(request.getParameter("resource")).redirectUri(request.getParameter("redirect_uri"))
                .requestDigest(digest).requestCiphertext(cipher.encrypt(realm, "browser-interaction", interactionId, json))
                .browserBindingDigest(Digests.sha256Hex(binding)).clientBrowserBindingDigest(edgeBinding)
                .csrfDigest(Digests.sha256Hex(csrf.getToken())).requestedScopes(List.copyOf(scopes)).approvedScopes(List.of())
                .codeChallenge(request.getParameter("code_challenge")).codeChallengeMethod("S256").state("PENDING")
                .expiresAt(clock.instant().plusSeconds(300)).retainUntil(clock.instant().plusSeconds(86_700)).build();
        interaction = interactions.save(realm, interaction, 0L);
        setCookie(request, response, name("interaction", realm), interactionId, Duration.ofMinutes(5));
        request.setAttribute(INTERACTION_ATTRIBUTE, interaction);
    }

    @Override
    @Transactional(readOnly = true)
    public SavedRequest getRequest(HttpServletRequest request, HttpServletResponse response) {
        if (cookie(request, name("interaction", realm(request))) == null) { return null; }
        var interaction = require(request, false);
        var parameters = parameters(realm(request), interaction);
        URI destination = URI.create(realm(request).getIssuer().toASCIIString() + "/oauth2/authorize?" + query(parameters));
        return new DefaultSavedRequest(new HttpServletRequestWrapper(request) {
            @Override public String getMethod() { return "GET"; }
            @Override public Map<String, String[]> getParameterMap() { return Collections.unmodifiableMap(parameters); }
            @Override public String getParameter(String name) { var values = parameters.get(name); return values == null ? null : values[0]; }
            @Override public String[] getParameterValues(String name) { return parameters.get(name); }
            @Override public java.util.Enumeration<String> getParameterNames() { return Collections.enumeration(parameters.keySet()); }
            @Override public String getQueryString() { return destination.getRawQuery(); }
            @Override public String getRequestURI() { return destination.getRawPath(); }
            @Override public StringBuffer getRequestURL() { return new StringBuffer(destination.toASCIIString().split("\\?", 2)[0]); }
            @Override public String getScheme() { return "https"; }
            @Override public String getServerName() { return destination.getHost(); }
            @Override public int getServerPort() { return destination.getPort() < 0 ? 443 : destination.getPort(); }
        });
    }

    @Override public HttpServletRequest getMatchingRequest(HttpServletRequest request, HttpServletResponse response) { return null; }
    @Override public void removeRequest(HttpServletRequest request, HttpServletResponse response) {
        // The grant transaction consumes the SQL interaction together with the authorization code.
    }

    @Transactional(readOnly = true)
    public OAuthInteractionBO require(HttpServletRequest request, boolean lock) {
        var realm = realm(request);
        String id = cookie(request, name("interaction", realm));
        if (id == null) { throw rejected(); }
        var interaction = (lock ? interactions.findByInteractionIdForUpdate(realm, id) : interactions.findByInteractionId(realm, id))
                .orElseThrow(OAuthBrowserInteractionComponent::rejected);
        var csrf = loadToken(request);
        if (!LIVE.contains(interaction.getState()) || !interaction.getExpiresAt().isAfter(clock.instant())) { throw rejected("OAUTH_INTERACTION_NOT_LIVE"); }
        if (!interaction.getBrowserBindingDigest().equals(bindingDigest(request))) { throw rejected("OAUTH_INTERACTION_BROWSER_MISMATCH"); }
        if (csrf == null || !interaction.getCsrfDigest().equals(Digests.sha256Hex(csrf.getToken()))) { throw rejected("OAUTH_INTERACTION_CSRF_MISMATCH"); }
        request.setAttribute(INTERACTION_ATTRIBUTE, interaction);
        return interaction;
    }

    @Transactional
    public OAuthAuthenticationJwtService.Issued completeLogin(HttpServletRequest request, String subject) {
        var realm = realm(request);
        realms.findByRealmKeyForUpdate(realm).orElseThrow(OAuthBrowserInteractionComponent::rejected);
        var interaction = require(request, true);
        if (!"PENDING".equals(interaction.getState()) || !"AUTHORIZATION".equals(interaction.getPurpose())) { throw rejected(); }
        var issued = authenticationJwts.issue(realm, interaction.getClientPk(), subject, interaction.getBrowserBindingDigest());
        long version = interaction.getVersion();
        interaction.setVersion(version + 1).setAuthenticationJtiDigest(issued.fact().getJtiDigest()).setRestrictedSubject(subject)
                .setState("AUTHENTICATED");
        interactions.save(realm, interaction, version);
        return issued;
    }

    /** Called inside the native SAS transaction, so code/consent facts and interaction consumption commit together. */
    public OAuthInteractionBO advanceAuthorization(HttpServletRequest request, String subject, String authenticationDigest,
            List<String> approvedScopes, boolean complete) {
        var interaction = require(request, true);
        if (interaction.getRestrictedSubject() != null && !subject.equals(interaction.getRestrictedSubject())) { throw rejected("OAUTH_INTERACTION_SUBJECT_MISMATCH"); }
        if (interaction.getAuthenticationJtiDigest() != null && !authenticationDigest.equals(interaction.getAuthenticationJtiDigest())) { throw rejected("OAUTH_INTERACTION_AUTHENTICATION_MISMATCH"); }
        if (!interaction.getRequestedScopes().containsAll(approvedScopes)) { throw rejected("OAUTH_INTERACTION_SCOPE_MISMATCH"); }
        long version = interaction.getVersion();
        interaction.setVersion(version + 1).setRestrictedSubject(subject).setAuthenticationJtiDigest(authenticationDigest)
                .setApprovedScopes(List.copyOf(approvedScopes)).setState(complete ? "CONSUMED" : "CONSENT_REQUIRED")
                .setConsumedAt(complete ? clock.instant() : null);
        return interactions.save(realm(request), interaction, version);
    }

    public void cancelAuthorization(HttpServletRequest request) {
        var interaction = require(request, true);
        long version = interaction.getVersion();
        interaction.setVersion(version + 1).setState("CANCELLED").setFailureCode("CONSENT_DENIED");
        interactions.save(realm(request), interaction, version);
    }

    /** A mandatory password change creates a separate restricted purpose and never issues an SSO credential. */
    @Transactional
    public void requirePasswordChange(HttpServletRequest request, HttpServletResponse response, String subject) {
        var realm = realm(request);
        realms.findByRealmKeyForUpdate(realm).orElseThrow(OAuthBrowserInteractionComponent::rejected);
        var original = require(request, true);
        if (!"AUTHORIZATION".equals(original.getPurpose()) || !"PENDING".equals(original.getState())) { throw rejected(); }
        String id = secret();
        var restricted = original.toBuilder().id(null).version(0L).interactionId(id).purpose("PASSWORD_CHANGE")
                .restrictedSubject(subject).authenticationJtiDigest(null)
                .requestCiphertext(cipher.encrypt(realm, "browser-interaction", id,
                        cipher.decrypt(realm, "browser-interaction", original.getInteractionId(), original.getRequestCiphertext())))
                .state("PENDING").build();
        long version = original.getVersion();
        original.setVersion(version + 1).setState("CANCELLED").setFailureCode("PASSWORD_CHANGE_REQUIRED");
        interactions.save(realm, original, version);
        interactions.save(realm, restricted, 0L);
        setCookie(request, response, name("interaction", realm), id, Duration.between(clock.instant(), restricted.getExpiresAt()));
        setCookie(request, response, name("authn", realm), "", Duration.ZERO);
    }

    @Transactional
    public String changeRequiredPassword(HttpServletRequest request, char[] oldPassword, char[] newPassword) {
        var realm = realm(request);
        realms.findByRealmKeyForUpdate(realm).orElseThrow(OAuthBrowserInteractionComponent::rejected);
        var interaction = require(request, true);
        if (!"PASSWORD_CHANGE".equals(interaction.getPurpose()) || !"PENDING".equals(interaction.getState())
                || interaction.getRestrictedSubject() == null || interaction.getAuthenticationJtiDigest() != null) { throw rejected(); }
        identities.changePassword(interaction.getRestrictedSubject(), oldPassword, newPassword, clock.instant());
        long version = interaction.getVersion();
        interaction.setVersion(version + 1).setState("CONSUMED").setConsumedAt(clock.instant());
        interactions.save(realm, interaction, version);
        return realm.getIssuer().getRawPath() + "/oauth2/authorize?" + query(parameters(realm, interaction));
    }

    @Transactional
    public void beginLogout(HttpServletRequest request, HttpServletResponse response,
            org.springframework.security.core.Authentication authentication) {
        var realm = realm(request);
        if (!"GET".equals(request.getMethod()) || !authentication.isAuthenticated()
                || !(authentication.getDetails() instanceof Map<?, ?> details)
                || !(details.get(OAuthAuthenticationJwtService.AUTHENTICATION_DIGEST) instanceof String authenticationDigest)
                || !Set.of("client_id", "post_logout_redirect_uri", "state").containsAll(request.getParameterMap().keySet())
                || request.getParameterMap().values().stream().anyMatch(value -> value.length != 1 || value[0] == null || value[0].length() > 2048)) {
            throw rejected();
        }
        Long clientPk = null;
        String redirect = request.getParameter("post_logout_redirect_uri");
        String clientId = request.getParameter("client_id");
        if (redirect != null || clientId != null) {
            var client = clients.findByClientId(realm, clientId).filter(value -> value.getStatus() == OAuthClient.Status.ACTIVE)
                    .orElseThrow(OAuthBrowserInteractionComponent::rejected);
            if (redirect == null || !client.getPostLogoutRedirectUris().contains(redirect)) { throw rejected(); }
            clientPk = client.getId();
        }
        String state = request.getParameter("state");
        if (state != null && (redirect == null || !state.matches("[A-Za-z0-9._~-]{1,256}"))) { throw rejected(); }
        var csrf = loadToken(request);
        if (csrf == null) { csrf = generateToken(request); saveToken(csrf, request, response); }
        String id = secret();
        String json;
        try { json = mapper.writeValueAsString(request.getParameterMap()); }
        catch (com.fasterxml.jackson.core.JsonProcessingException invalid) { throw new IllegalStateException("OAUTH_LOGOUT_ENCODING_FAILED", invalid); }
        var interaction = OAuthInteractionBO.builder().interactionId(id).purpose("LOGOUT").clientPk(clientPk).redirectUri(redirect)
                .requestDigest(TenantLoginAuthenticationFilter.authorizationRequestDigest(realm.getIssuer(), request.getParameterMap()))
                .requestCiphertext(cipher.encrypt(realm, "browser-interaction", id, json)).browserBindingDigest(bindingDigest(request))
                .csrfDigest(Digests.sha256Hex(csrf.getToken())).authenticationJtiDigest(authenticationDigest).restrictedSubject(authentication.getName())
                .requestedScopes(List.of()).approvedScopes(List.of()).state("PENDING").expiresAt(clock.instant().plusSeconds(300))
                .retainUntil(clock.instant().plusSeconds(86_700)).build();
        interactions.save(realm, interaction, 0L);
        setCookie(request, response, name("interaction", realm), id, Duration.ofMinutes(5));
    }

    @Transactional
    public String completeLogout(HttpServletRequest request, org.springframework.security.core.Authentication authentication) {
        var realm = realm(request);
        realms.findByRealmKeyForUpdate(realm).orElseThrow(OAuthBrowserInteractionComponent::rejected);
        var interaction = require(request, true);
        if (!"LOGOUT".equals(interaction.getPurpose()) || !authentication.isAuthenticated()
                || !interaction.getRestrictedSubject().equals(authentication.getName()) || !(authentication.getDetails() instanceof Map<?, ?> details)
                || !interaction.getAuthenticationJtiDigest().equals(details.get(OAuthAuthenticationJwtService.AUTHENTICATION_DIGEST))) { throw rejected(); }
        if (interaction.getRedirectUri() != null && clients.findById(realm, interaction.getClientPk())
                .filter(client -> client.getStatus() == OAuthClient.Status.ACTIVE
                        && client.getPostLogoutRedirectUris().contains(interaction.getRedirectUri())).isEmpty()) { throw rejected(); }
        sso.logout(realm, interaction.getAuthenticationJtiDigest(), interaction.getBrowserBindingDigest(), interaction.getRestrictedSubject());
        long version = interaction.getVersion();
        interaction.setVersion(version + 1).setState("CONSUMED").setConsumedAt(clock.instant());
        interactions.save(realm, interaction, version);
        if (interaction.getRedirectUri() == null) { return null; }
        var values = parameters(realm, interaction);
        String[] state = values.get("state");
        return state == null ? interaction.getRedirectUri() : org.springframework.web.util.UriComponentsBuilder.fromUriString(interaction.getRedirectUri())
                .queryParam("state", encode(state[0])).build(true).toUriString();
    }

    public Map<String, String[]> parameters(TrustedRealmBO realm, OAuthInteractionBO interaction) {
        try {
            var values = mapper.readValue(cipher.decrypt(realm, "browser-interaction", interaction.getInteractionId(),
                    interaction.getRequestCiphertext()), new TypeReference<LinkedHashMap<String, String[]>>() { });
            if (!interaction.getRequestDigest().equals(TenantLoginAuthenticationFilter.authorizationRequestDigest(realm.getIssuer(), values))) {
                throw rejected();
            }
            return values;
        } catch (com.fasterxml.jackson.core.JsonProcessingException invalid) { throw new IllegalStateException("OAUTH_INTERACTION_DECODING_FAILED", invalid); }
    }

    @Override public CsrfToken generateToken(HttpServletRequest request) { return new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", secret()); }
    @Override public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
        setCookie(request, response, name("csrf", realm(request)), token == null ? "" : token.getToken(),
                token == null ? Duration.ZERO : Duration.ofMinutes(5));
    }
    @Override public CsrfToken loadToken(HttpServletRequest request) {
        String token = cookie(request, name("csrf", realm(request)));
        return token == null ? null : new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", token);
    }

    public TrustedRealmBO realm(HttpServletRequest request) {
        String path = request.getRequestURI();
        var matcher = java.util.regex.Pattern.compile("^(/tenants/[1-9][0-9]{0,18})/(?:login|consent|oauth2/authorize|logout|password-change)$").matcher(path);
        if (!matcher.matches()) { throw rejected(); }
        return issuers.resolveExactIssuer(URI.create(publicOrigin.toASCIIString().replaceAll("/+$", "") + matcher.group(1)));
    }

    public String bindingDigest(HttpServletRequest request) {
        String binding = cookie(request, BINDING_COOKIE);
        return binding == null ? null : Digests.sha256Hex(binding);
    }

    public static String name(String purpose, TrustedRealmBO realm) {
        return "__Host-idp-" + purpose + "-" + Digests.sha256Hex(realm.getIssuer().toASCIIString()).substring(0, 16);
    }

    public static String cookie(HttpServletRequest request, String name) {
        Object generated = request.getAttribute(OAuthBrowserInteractionComponent.class.getName() + name);
        if (generated instanceof String value) { return value.isEmpty() ? null : value; }
        String result = null;
        for (Cookie cookie : request.getCookies() == null ? new Cookie[0] : request.getCookies()) {
            if (!name.equals(cookie.getName())) { continue; }
            if (result != null || cookie.getValue() == null || cookie.getValue().isBlank() || cookie.getValue().length() > 16_384) { throw rejected(); }
            result = cookie.getValue();
        }
        return result;
    }

    public static void setCookie(HttpServletRequest request, HttpServletResponse response, String name, String value, Duration age) {
        if (response == null) { throw new IllegalStateException("OAUTH_BROWSER_RESPONSE_REQUIRED"); }
        response.addHeader("Set-Cookie", ResponseCookie.from(name, value).path("/").httpOnly(true).secure(true).sameSite("Lax").maxAge(age).build().toString());
        request.setAttribute(OAuthBrowserInteractionComponent.class.getName() + name, value);
    }

    private String secret() { byte[] value = new byte[32]; random.nextBytes(value); return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
    public static String query(Map<String, String[]> parameters) {
        return parameters.entrySet().stream().sorted(Map.Entry.comparingByKey()).map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue()[0]))
                .collect(java.util.stream.Collectors.joining("&"));
    }
    private static String encode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8); }
    private static OAuth2AuthenticationException rejected() { return new OAuth2AuthenticationException(new OAuth2Error("invalid_request", "Browser interaction rejected", null)); }
    private static OAuth2AuthenticationException rejected(String code) {
        return new OAuth2AuthenticationException(new OAuth2Error("invalid_request", "Browser interaction rejected", null), new IllegalArgumentException(code));
    }
}
