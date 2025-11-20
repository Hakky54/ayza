/*
 * Copyright 2019 Thunderberry.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nl.altindag.ssl.provider;

import java.security.Provider;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.ProviderUtils ProviderUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 *
 * @author Hakan Altindag
 */
public final class FenixProvider extends Provider {

    public FenixProvider() {
        super("Fenix", 1.0, "Fenix Security Provider");

        put("SSLContext.TLS", "nl.altindag.ssl.sslcontext.FenixSSLContextSpi");

        put("Alg.Alias.SSLContext.SSL", "TLS");
        put("Alg.Alias.SSLContext.SSLv2", "TLS");
        put("Alg.Alias.SSLContext.SSLv3", "TLS");
        put("Alg.Alias.SSLContext.TLSv1", "TLS");
        put("Alg.Alias.SSLContext.TLSv1.1", "TLS");
        put("Alg.Alias.SSLContext.TLSv1.2", "TLS");
        put("Alg.Alias.SSLContext.TLSv1.3", "TLS");
        put("Alg.Alias.SSLContext.Default", "TLS");
    }

}