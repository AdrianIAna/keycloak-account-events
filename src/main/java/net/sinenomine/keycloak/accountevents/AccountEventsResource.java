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

import java.util.List;
import java.util.stream.Stream;

import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.NoCache;

import org.keycloak.events.EventQuery;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.EventType;
import org.keycloak.models.AccountRoles;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.protocol.oidc.AccessTokenIntrospectionProvider;
import org.keycloak.protocol.oidc.AccessTokenIntrospectionProviderFactory;
import org.keycloak.protocol.oidc.TokenIntrospectionProvider;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.EventRepresentation;
import org.keycloak.services.cors.Cors;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;
import org.keycloak.services.util.DateUtil;

/**
 * Account-scoped login-history resource serving
 * {@code GET /realms/{realm}/account-events/me}: the authenticated caller's own
 * authentication events (LOGIN, LOGOUT, LOGIN_ERROR, …) from the realm event
 * store.
 *
 * <p>The request pipeline mirrors Keycloak's built-in account API gatekeeping
 * (see {@code AccountLoader}): bearer-token authentication, lightweight-token
 * claim recovery via introspection, an {@code account} audience check, CORS
 * origin enforcement, service-account rejection, and finally the
 * {@code view-profile}/{@code manage-account} role requirement. Results are
 * always hard-scoped to the token's own subject — there is no user-id request
 * parameter, so a caller can never read another user's events.
 */
public class AccountEventsResource {

    private static final Logger log = Logger.getLogger(AccountEventsResource.class);

    /** Default upper bound on the number of events returned in a single response. */
    static final int DEFAULT_MAX_RESULTS = 1000;

    private final KeycloakSession session;
    private final int maxResultsCap;

    public AccountEventsResource(KeycloakSession session, int maxResultsCap) {
        this.session = session;
        this.maxResultsCap = maxResultsCap;
    }

    /** CORS preflight for browser callers, mirroring the built-in account API. */
    @OPTIONS
    @Path("me")
    public Response preflight() {
        requireEnabledAccountClient();
        return Cors.builder().auth().allowedMethods("GET", "OPTIONS").preflight().add(Response.ok());
    }

    /**
     * @param types     optional event-type filter (e.g. {@code LOGIN}, {@code LOGIN_ERROR})
     * @param client    optional client-id filter
     * @param dateFrom  optional start date ({@code yyyy-MM-dd} or epoch millis)
     * @param dateTo    optional end date ({@code yyyy-MM-dd} or epoch millis)
     * @param ipAddress optional IP-address filter
     * @param first     pagination offset (clamped to {@code >= 0})
     * @param max       maximum results (clamped to the configured cap, default 1000)
     * @return the caller's own events, newest first
     */
    @GET
    @Path("me")
    @Produces(MediaType.APPLICATION_JSON)
    @NoCache
    public Stream<EventRepresentation> getEvents(
            @QueryParam("type") List<String> types,
            @QueryParam("client") String client,
            @QueryParam("dateFrom") String dateFrom,
            @QueryParam("dateTo") String dateTo,
            @QueryParam("ipAddress") String ipAddress,
            @QueryParam("first") @DefaultValue("0") int first,
            @QueryParam("max") @DefaultValue("100") int max) {

        requireEnabledAccountClient();

        AuthResult authResult = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
        if (authResult == null || authResult.user() == null) {
            throw new NotAuthorizedException("Bearer realm=\"account\"");
        }

        AccessToken token = resolveToken(authResult);
        if (token == null || !token.hasAudience(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID)) {
            throw new NotAuthorizedException("Invalid audience for client " + Constants.ACCOUNT_MANAGEMENT_CLIENT_ID);
        }

        Cors.builder().checkAllowedOrigins(token).allowedMethods("GET").auth().add();

        if (authResult.user().getServiceAccountClientLink() != null) {
            throw new NotAuthorizedException("Service accounts are not allowed to access this service");
        }

        if (!hasAccountAccess(token)) {
            throw new ForbiddenException("Requires account access (view-profile or manage-account)");
        }

        RealmModel realm = session.getContext().getRealm();
        UserModel user = authResult.user();

        EventStoreProvider eventStore = session.getProvider(EventStoreProvider.class);
        if (eventStore == null) {
            log.warn("account-events: no EventStoreProvider configured");
            return Stream.empty();
        }

        EventQuery query = eventStore.createQuery()
                .realm(realm.getId())
                .user(user.getId())
                .orderByDescTime();

        EventType[] parsedTypes = parseEventTypes(types);
        if (parsedTypes != null) {
            query.type(parsedTypes);
        }
        if (client != null) {
            query.client(client);
        }
        if (dateFrom != null) {
            try {
                query.fromDate(DateUtil.toStartOfDay(dateFrom));
            } catch (RuntimeException e) {
                throw new BadRequestException("Invalid value for 'dateFrom', expected format is yyyy-MM-dd or an Epoch timestamp");
            }
        }
        if (dateTo != null) {
            try {
                query.toDate(DateUtil.toEndOfDay(dateTo));
            } catch (RuntimeException e) {
                throw new BadRequestException("Invalid value for 'dateTo', expected format is yyyy-MM-dd or an Epoch timestamp");
            }
        }
        if (ipAddress != null) {
            query.ipAddress(ipAddress);
        }

        query.firstResult(Math.max(first, 0));
        query.maxResults(Math.min(Math.max(max, 0), maxResultsCap));

        return query.getResultStream().map(ModelToRepresentation::toRepresentation);
    }

    /**
     * The endpoint exists only while the realm's {@code account} client does,
     * mirroring the built-in account API ({@code AccountLoader}): a realm that
     * disabled the account client gets {@code 404}, not served history.
     */
    private void requireEnabledAccountClient() {
        ClientModel accountClient = session.getContext().getRealm()
                .getClientByClientId(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID);
        if (accountClient == null || !accountClient.isEnabled()) {
            throw new NotFoundException("account management not enabled");
        }
    }

    /**
     * Resolve the effective access token. Lightweight access tokens omit the
     * {@code aud} and {@code resource_access} claims from the wire token; recover
     * them via the introspection transform, exactly as the built-in account API
     * does ({@code AccountLoader}).
     */
    private AccessToken resolveToken(AuthResult authResult) {
        AccessToken token = authResult.token();
        if (token != null
                && (token.getAudience() == null
                        || token.getResourceAccess(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID) == null)) {
            AccessTokenIntrospectionProvider provider = (AccessTokenIntrospectionProvider) session.getProvider(
                    TokenIntrospectionProvider.class, AccessTokenIntrospectionProviderFactory.ACCESS_TOKEN_TYPE);
            if (provider != null) {
                token = provider.transformAccessToken(token, authResult.session());
            }
        }
        return token;
    }

    /**
     * Whether the token carries the {@code account} client's {@code view-profile}
     * or {@code manage-account} role.
     */
    static boolean hasAccountAccess(AccessToken token) {
        if (token == null) {
            return false;
        }
        AccessToken.Access access = token.getResourceAccess(Constants.ACCOUNT_MANAGEMENT_CLIENT_ID);
        return access != null
                && (access.isUserInRole(AccountRoles.VIEW_PROFILE)
                        || access.isUserInRole(AccountRoles.MANAGE_ACCOUNT));
    }

    /**
     * Parse the {@code type} query parameter; {@code null} means no type filter.
     *
     * @throws BadRequestException if any value is not a valid {@link EventType}
     */
    static EventType[] parseEventTypes(List<String> types) {
        if (types == null || types.isEmpty()) {
            return null;
        }
        EventType[] parsed = new EventType[types.size()];
        for (int i = 0; i < parsed.length; i++) {
            String value = types.get(i);
            try {
                parsed[i] = EventType.valueOf(value);
            } catch (IllegalArgumentException | NullPointerException e) {
                throw new BadRequestException("Invalid value for 'type'");
            }
        }
        return parsed;
    }
}
