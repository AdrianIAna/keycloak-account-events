/*
 * Copyright 2026 Sine Nomine Associates and contributors
 * Author: Adrian Ana <aana@sinenomine.net>
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.sinenomine.keycloak.accountevents;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for the account-events realm resource. Registers the provider under
 * the realm-relative path segment returned by {@link #getId()}, so the endpoint
 * is served at {@code /realms/{realm}/account-events}.
 *
 * <p>Configuration (SPI {@code realm-restapi-extension}, provider
 * {@code account-events}):
 * <ul>
 *   <li>{@code max-results} — upper bound on events per response (default 1000),
 *       e.g. {@code --spi-realm-restapi-extension--account-events--max-results=5000}</li>
 * </ul>
 */
public class AccountEventsResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "account-events";

    private int maxResults = AccountEventsResource.DEFAULT_MAX_RESULTS;

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new AccountEventsResourceProvider(session, maxResults);
    }

    @Override
    public void init(Config.Scope config) {
        maxResults = config.getInt("max-results", AccountEventsResource.DEFAULT_MAX_RESULTS);
        if (maxResults <= 0) {
            // fail fast: a non-positive value would disable the cap entirely
            // (the JPA event query treats max < 0 as "no limit")
            throw new IllegalArgumentException(
                    "account-events: max-results must be a positive integer, got " + maxResults);
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no-op
    }

    @Override
    public void close() {
        // no-op
    }

    @Override
    public String getId() {
        return ID;
    }
}
