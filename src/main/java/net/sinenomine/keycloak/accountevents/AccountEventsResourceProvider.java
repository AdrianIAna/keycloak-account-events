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

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class AccountEventsResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;
    private final int maxResults;

    public AccountEventsResourceProvider(KeycloakSession session, int maxResults) {
        this.session = session;
        this.maxResults = maxResults;
    }

    @Override
    public Object getResource() {
        return new AccountEventsResource(session, maxResults);
    }

    @Override
    public void close() {
        // no-op
    }
}
