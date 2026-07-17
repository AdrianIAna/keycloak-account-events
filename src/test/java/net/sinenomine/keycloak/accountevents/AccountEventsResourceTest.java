/*
 * Copyright 2026 Adrian Ana and contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package net.sinenomine.keycloak.accountevents;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.stream.Stream;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.RuntimeDelegate;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import org.keycloak.events.EventQuery;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.EventType;
import org.keycloak.models.AccountRoles;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.AccessTokenIntrospectionProvider;
import org.keycloak.protocol.oidc.AccessTokenIntrospectionProviderFactory;
import org.keycloak.protocol.oidc.TokenIntrospectionProvider;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.utils.KeycloakSessionUtil;

class AccountEventsResourceTest {

    private static final String ACCOUNT = Constants.ACCOUNT_MANAGEMENT_CLIENT_ID;
    private static final int CAP = AccountEventsResource.DEFAULT_MAX_RESULTS;

    @BeforeAll
    static void pinRuntimeDelegate() {
        // JAX-RS exceptions build a Response in their constructor, which requires a
        // RuntimeDelegate. Two providers sit on the test classpath (resteasy-core for
        // tests, resteasy-reactive-common for @NoCache) — pin resteasy-core's; the
        // reactive one needs server components.
        RuntimeDelegate.setInstance(new org.jboss.resteasy.core.providerfactory.ResteasyProviderFactoryImpl());
    }

    @AfterEach
    void clearThreadLocalSession() {
        KeycloakSessionUtil.setKeycloakSession(null);
    }

    // ---- hasAccountAccess ----------------------------------------------------

    @Test
    void hasAccountAccess_nullToken_false() {
        assertFalse(AccountEventsResource.hasAccountAccess(null));
    }

    @Test
    void hasAccountAccess_noAccountResourceAccess_false() {
        AccessToken token = mock(AccessToken.class);
        when(token.getResourceAccess(ACCOUNT)).thenReturn(null);
        assertFalse(AccountEventsResource.hasAccountAccess(token));
    }

    @Test
    void hasAccountAccess_accountAccessButNoRole_false() {
        // unstubbed isUserInRole(...) defaults to false
        assertFalse(AccountEventsResource.hasAccountAccess(tokenWithAccountRole(null)));
    }

    @Test
    void hasAccountAccess_viewProfile_true() {
        assertTrue(AccountEventsResource.hasAccountAccess(tokenWithAccountRole(AccountRoles.VIEW_PROFILE)));
    }

    @Test
    void hasAccountAccess_manageAccount_true() {
        assertTrue(AccountEventsResource.hasAccountAccess(tokenWithAccountRole(AccountRoles.MANAGE_ACCOUNT)));
    }

    // ---- parseEventTypes -----------------------------------------------------

    @Test
    void parseEventTypes_null_returnsNull() {
        assertNull(AccountEventsResource.parseEventTypes(null));
    }

    @Test
    void parseEventTypes_empty_returnsNull() {
        assertNull(AccountEventsResource.parseEventTypes(List.of()));
    }

    @Test
    void parseEventTypes_valid_parsed() {
        assertArrayEquals(
                new EventType[] {EventType.LOGIN, EventType.LOGIN_ERROR},
                AccountEventsResource.parseEventTypes(List.of("LOGIN", "LOGIN_ERROR")));
    }

    @Test
    void parseEventTypes_invalid_badRequest() {
        assertThrows(BadRequestException.class,
                () -> AccountEventsResource.parseEventTypes(List.of("NOT_A_TYPE")));
    }

    // ---- account client gate ---------------------------------------------------

    @Test
    void getEvents_accountClientMissing_notFound() {
        KeycloakSession session = sessionWithAccountClient(null);
        assertThrows(NotFoundException.class, () -> drain(session));
    }

    @Test
    void getEvents_accountClientDisabled_notFound() {
        ClientModel disabled = mock(ClientModel.class); // isEnabled() defaults to false
        KeycloakSession session = sessionWithAccountClient(disabled);
        assertThrows(NotFoundException.class, () -> drain(session));
    }

    // ---- getEvents: gate ordering ---------------------------------------------

    @Test
    void getEvents_noToken_unauthorized() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        try (var ignored = mockAuthenticator(null)) {
            assertThrows(NotAuthorizedException.class, () -> drain(session));
        }
    }

    @Test
    void getEvents_missingUser_unauthorized() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        AuthResult auth = mock(AuthResult.class);
        when(auth.user()).thenReturn(null);
        try (var ignored = mockAuthenticator(auth)) {
            assertThrows(NotAuthorizedException.class, () -> drain(session));
        }
    }

    @Test
    void getEvents_noIntrospectionProvider_unauthorized() {
        // wire token missing aud/resource_access and no introspection provider
        // available → cannot establish the account audience → 401
        KeycloakSession session = sessionWithEnabledAccountClient();
        AuthResult auth = authFor("u", mock(AccessToken.class));
        try (var ignored = mockAuthenticator(auth)) {
            assertThrows(NotAuthorizedException.class, () -> drain(session));
        }
    }

    @Test
    void getEvents_recoveredTokenWrongAudience_unauthorized() {
        // introspection recovers a token, but its aud still lacks "account" → 401
        KeycloakSession session = sessionWithEnabledAccountClient();
        AccessToken wireToken = mock(AccessToken.class);
        AccessToken recovered = mock(AccessToken.class); // hasAudience defaults to false
        when(recovered.getAudience()).thenReturn(new String[] {"other-client"});
        UserSessionModel userSession = mock(UserSessionModel.class);
        AccessTokenIntrospectionProvider introspection = mock(AccessTokenIntrospectionProvider.class);
        when(introspection.transformAccessToken(wireToken, userSession)).thenReturn(recovered);
        when(session.getProvider(TokenIntrospectionProvider.class,
                AccessTokenIntrospectionProviderFactory.ACCESS_TOKEN_TYPE)).thenReturn(introspection);
        AuthResult auth = authFor("u", wireToken);
        when(auth.session()).thenReturn(userSession);
        try (var ignored = mockAuthenticator(auth)) {
            assertThrows(NotAuthorizedException.class, () -> drain(session));
        }
    }

    @Test
    void getEvents_serviceAccountToken_unauthorized_afterCorsRan() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        Cors cors = corsFor(session);
        AccessToken token = tokenWithAccountRole(AccountRoles.VIEW_PROFILE);
        UserModel serviceAccount = mock(UserModel.class);
        when(serviceAccount.getServiceAccountClientLink()).thenReturn("some-client");
        AuthResult auth = mock(AuthResult.class);
        when(auth.user()).thenReturn(serviceAccount);
        when(auth.token()).thenReturn(token);
        try (var ignored = mockAuthenticator(auth)) {
            assertThrows(NotAuthorizedException.class, () -> drain(session));
        }
        // pins upstream gate order: CORS origin enforcement runs before the
        // service-account rejection
        verify(cors).checkAllowedOrigins(token);
    }

    @Test
    void getEvents_accountAudienceButNoRole_forbidden() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        corsFor(session);
        AuthResult auth = authFor("u", tokenWithAccountRole(null)); // aud ok, roles absent
        try (var ignored = mockAuthenticator(auth)) {
            assertThrows(ForbiddenException.class, () -> drain(session));
        }
    }

    // ---- getEvents: lightweight-token introspection fallback ------------------

    @Test
    void getEvents_lightweightToken_recoveredViaIntrospection() {
        EventQuery query = emptyQuery();
        KeycloakSession session = authorizedSession("realm-1", query);

        // wire token missing aud + resource_access → introspection must recover them
        AccessToken wireToken = mock(AccessToken.class);
        AccessToken fullToken = tokenWithAccountRole(AccountRoles.VIEW_PROFILE);
        UserSessionModel userSession = mock(UserSessionModel.class);
        AccessTokenIntrospectionProvider introspection = mock(AccessTokenIntrospectionProvider.class);
        when(introspection.transformAccessToken(wireToken, userSession)).thenReturn(fullToken);
        when(session.getProvider(TokenIntrospectionProvider.class,
                AccessTokenIntrospectionProviderFactory.ACCESS_TOKEN_TYPE)).thenReturn(introspection);

        AuthResult auth = authFor("user-1", wireToken);
        when(auth.session()).thenReturn(userSession);

        try (var ignored = mockAuthenticator(auth)) {
            new AccountEventsResource(session, CAP)
                    .getEvents(null, null, null, null, null, 0, 100).close();
        }

        verify(introspection).transformAccessToken(wireToken, userSession);
        verify(query).user("user-1");
    }

    @Test
    void getEvents_fullToken_skipsIntrospection() {
        EventQuery query = emptyQuery();
        KeycloakSession session = authorizedSession("realm-1", query);
        AuthResult auth = authFor("user-1", tokenWithAccountRole(AccountRoles.VIEW_PROFILE));

        try (var ignored = mockAuthenticator(auth)) {
            new AccountEventsResource(session, CAP)
                    .getEvents(null, null, null, null, null, 0, 100).close();
        }

        verify(session, never()).getProvider(eq(TokenIntrospectionProvider.class), any(String.class));
    }

    // ---- getEvents: authorized path -------------------------------------------

    @Test
    void getEvents_authorized_scopedToOwnUserAndRealm_withCors() {
        EventQuery query = emptyQuery();
        KeycloakSession session = authorizedSession("realm-42", query);
        Cors cors = corsFor(session);
        AccessToken token = tokenWithAccountRole(AccountRoles.VIEW_PROFILE);
        AuthResult auth = authFor("user-7", token);

        try (var ignored = mockAuthenticator(auth)) {
            new AccountEventsResource(session, CAP)
                    .getEvents(null, null, null, null, null, 0, 100).close();
        }

        // hard-scoped to the caller's own realm + user id — never a request param
        verify(query).realm("realm-42");
        verify(query).user("user-7");
        // CORS origin enforcement ran against the resolved token
        verify(cors).checkAllowedOrigins(token);
        verify(cors).add();
    }

    @Test
    void getEvents_clampsPagination_aboveCapAndNegative() {
        EventQuery query = emptyQuery();
        KeycloakSession session = authorizedSession("r", query);
        AuthResult auth = authFor("u", tokenWithAccountRole(AccountRoles.VIEW_PROFILE));

        try (var ignored = mockAuthenticator(auth)) {
            new AccountEventsResource(session, CAP)
                    .getEvents(null, null, null, null, null, -10, 5000).close();
        }

        verify(query).firstResult(0);
        verify(query).maxResults(CAP);
    }

    @Test
    void getEvents_belowCapMax_passesThrough() {
        EventQuery query = emptyQuery();
        KeycloakSession session = authorizedSession("r", query);
        AuthResult auth = authFor("u", tokenWithAccountRole(AccountRoles.VIEW_PROFILE));

        try (var ignored = mockAuthenticator(auth)) {
            new AccountEventsResource(session, CAP)
                    .getEvents(null, null, null, null, null, 5, 50).close();
        }

        verify(query).firstResult(5);
        verify(query).maxResults(50);
    }

    @Test
    void getEvents_invalidType_badRequest() {
        KeycloakSession session = authorizedSession("r", emptyQuery());
        corsFor(session);
        AuthResult auth = authFor("u", tokenWithAccountRole(AccountRoles.VIEW_PROFILE));

        try (var ignored = mockAuthenticator(auth)) {
            AccountEventsResource resource = new AccountEventsResource(session, CAP);
            assertThrows(BadRequestException.class,
                    () -> resource.getEvents(List.of("NOPE"), null, null, null, null, 0, 100));
        }
    }

    @Test
    void getEvents_isMarkedNoCache() throws NoSuchMethodException {
        // Login history is per-user data on a GET — responses must not be cached.
        var method = AccountEventsResource.class.getMethod("getEvents",
                List.class, String.class, String.class, String.class, String.class, int.class, int.class);
        assertTrue(method.isAnnotationPresent(org.jboss.resteasy.reactive.NoCache.class),
                "getEvents must carry @NoCache");
    }

    // ---- preflight -------------------------------------------------------------

    @Test
    void preflight_addsCorsHeaders() {
        KeycloakSession session = sessionWithEnabledAccountClient();
        Cors cors = corsFor(session);
        when(cors.add(any(Response.ResponseBuilder.class))).thenReturn(Response.ok().build());

        Response response = new AccountEventsResource(session, CAP).preflight();

        assertEquals(200, response.getStatus());
        verify(cors).preflight();
        verify(cors).allowedMethods("GET", "OPTIONS");
    }

    @Test
    void preflight_accountClientDisabled_notFound() {
        ClientModel disabled = mock(ClientModel.class);
        KeycloakSession session = sessionWithAccountClient(disabled);
        AccountEventsResource resource = new AccountEventsResource(session, CAP);
        assertThrows(NotFoundException.class, resource::preflight);
    }

    // ---- helpers -------------------------------------------------------------

    /**
     * Token whose {@code aud} contains {@code account}; {@code role} may be null
     * for an account-audience token without account roles.
     */
    private static AccessToken tokenWithAccountRole(String role) {
        AccessToken.Access access = mock(AccessToken.Access.class);
        if (role != null) {
            when(access.isUserInRole(role)).thenReturn(true);
        }
        AccessToken token = mock(AccessToken.class);
        when(token.getResourceAccess(ACCOUNT)).thenReturn(access);
        when(token.getAudience()).thenReturn(new String[] {ACCOUNT});
        when(token.hasAudience(ACCOUNT)).thenReturn(true);
        return token;
    }

    private static AuthResult authFor(String userId, AccessToken token) {
        UserModel user = mock(UserModel.class);
        when(user.getId()).thenReturn(userId);
        AuthResult auth = mock(AuthResult.class);
        when(auth.user()).thenReturn(user);
        when(auth.token()).thenReturn(token);
        return auth;
    }

    private static EventQuery emptyQuery() {
        EventQuery query = mock(EventQuery.class, RETURNS_SELF);
        when(query.getResultStream()).thenReturn(Stream.empty());
        return query;
    }

    /** Session whose realm has the given {@code account} client (may be null). */
    private static KeycloakSession sessionWithAccountClient(ClientModel accountClient) {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getClientByClientId(ACCOUNT)).thenReturn(accountClient);
        KeycloakContext ctx = mock(KeycloakContext.class);
        when(ctx.getRealm()).thenReturn(realm);
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getContext()).thenReturn(ctx);
        return session;
    }

    private static KeycloakSession sessionWithEnabledAccountClient() {
        ClientModel accountClient = mock(ClientModel.class);
        when(accountClient.isEnabled()).thenReturn(true);
        return sessionWithAccountClient(accountClient);
    }

    /** Wire a Cors provider into the session and bind the thread-local. */
    private static Cors corsFor(KeycloakSession session) {
        Cors cors = mock(Cors.class, RETURNS_SELF);
        when(session.getProvider(Cors.class)).thenReturn(cors);
        // Cors.builder() resolves the session from the thread-local
        KeycloakSessionUtil.setKeycloakSession(session);
        return cors;
    }

    private static KeycloakSession authorizedSession(String realmId, EventQuery query) {
        KeycloakSession session = sessionWithEnabledAccountClient();
        when(session.getContext().getRealm().getId()).thenReturn(realmId);
        corsFor(session);
        EventStoreProvider store = mock(EventStoreProvider.class);
        when(store.createQuery()).thenReturn(query);
        when(session.getProvider(EventStoreProvider.class)).thenReturn(store);
        return session;
    }

    private static org.mockito.MockedConstruction<AppAuthManager.BearerTokenAuthenticator> mockAuthenticator(AuthResult result) {
        return mockConstruction(AppAuthManager.BearerTokenAuthenticator.class,
                (mockAuth, ctx) -> when(mockAuth.authenticate()).thenReturn(result));
    }

    private static void drain(KeycloakSession session) {
        try (Stream<?> s = new AccountEventsResource(session, CAP)
                .getEvents(null, null, null, null, null, 0, 100)) {
            s.forEach(x -> { });
        }
    }
}
