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
package nl.altindag.ssl.keymanager;

import nl.altindag.laleler.HostUtils;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.net.URI;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Represents an ordered list of {@link X509ExtendedKeyManager} with most-preferred managers first.
 * <p>
 * This is necessary because of the fine-print on {@link javax.net.ssl.SSLContext#init}:
 * Only the first instance of a particular key and/or key manager implementation type in the
 * array is used. (For example, only the first javax.net.ssl.X509KeyManager in the array will be used.)
 * The KeyManager can be build from one or more of any combination provided within the {@link nl.altindag.ssl.util.KeyManagerUtils.KeyManagerBuilder KeyManagerUtils.KeyManagerBuilder}.
 * <br><br>
 * This includes:
 * <pre>
 *     - Any amount of custom KeyManagers
 *     - Any amount of custom Identities
 * </pre>
 *
 * <p>
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.KeyManagerUtils KeyManagerUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 * </p>
 *
 * @see <a href="http://stackoverflow.com/questions/1793979/registering-multiple-keystores-in-jvm">
 *     http://stackoverflow.com/questions/1793979/registering-multiple-keystores-in-jvm
 *     </a>
 * @see <a href="http://codyaray.com/2013/04/java-ssl-with-multiple-keystores">
 *     http://codyaray.com/2013/04/java-ssl-with-multiple-keystores
 *     </a>
 *
 * @author Cody Ray
 * @author Hakan Altindag
 */
public final class AggregatedX509ExtendedKeyManager extends X509ExtendedKeyManager implements CombinableX509KeyManager, RoutableX509KeyManager {

    final Map<String, X509ExtendedKeyManager> keyManagers;
    private final Map<String, List<URI>> preferredAliasToHost;

    /**
     * Creates a new {@link AggregatedX509ExtendedKeyManager}.
     *
     * @param keyManagers the {@link X509ExtendedKeyManager}, ordered with the most-preferred managers first.
     */
    public AggregatedX509ExtendedKeyManager(Map<String, ? extends X509ExtendedKeyManager> keyManagers) {
        this(keyManagers, Collections.emptyMap());
    }

    /**
     * Creates a new {@link AggregatedX509ExtendedKeyManager}.
     *
     * @param keyManagers          the {@link X509ExtendedKeyManager}, ordered with the most-preferred managers first.
     * @param preferredAliasToHost the preferred client alias to be used for the given host
     */
    public AggregatedX509ExtendedKeyManager(Map<String, ? extends X509ExtendedKeyManager> keyManagers,
                                            Map<String, List<URI>> preferredAliasToHost) {
        this.keyManagers = Collections.synchronizedMap(new LinkedHashMap<>(keyManagers));
        this.preferredAliasToHost = new ConcurrentHashMap<>(preferredAliasToHost);
    }

    /**
     * Chooses the first non-null client alias returned from the delegate
     * {@link X509ExtendedKeyManager}, or {@code null} if there are no matches.
     */
    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return chooseClientAlias(
                socket,
                this::containsInetSocketAddress,
                HostUtils::extractHostAndPort,
                keyManager -> keyManager.chooseClientAlias(keyType, issuers, socket)
        );
    }

    /**
     * Chooses the first non-null client alias returned from the delegate
     * {@link X509ExtendedKeyManager}, or {@code null} if there are no matches.
     */
    @Override
    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine sslEngine) {
        return chooseClientAlias(
                sslEngine,
                Objects::nonNull,
                HostUtils::extractHostAndPort,
                keyManager -> keyManager.chooseEngineClientAlias(keyTypes, issuers, sslEngine)
        );
    }

    /**
     * Chooses the first non-null server alias returned from the delegate
     * {@link X509ExtendedKeyManager}, or {@code null} if there are no matches.
     */
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return chooseServerAlias(
                socket,
                SSLSocket.class::isInstance,
                aSocket -> ((SSLSocket) aSocket).getHandshakeSession(),
                keyManager -> keyManager.chooseServerAlias(keyType, issuers, socket)
        );
    }

    /**
     * Chooses the first non-null server alias returned from the delegate
     * {@link X509ExtendedKeyManager}, or {@code null} if there are no matches.
     */
    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine sslEngine) {
        return chooseServerAlias(
                sslEngine,
                Objects::nonNull,
                SSLEngine::getHandshakeSession,
                keyManager -> keyManager.chooseEngineServerAlias(keyType, issuers, sslEngine)
        );
    }

    /**
     * Returns the first non-null private key associated with the
     * given alias, or {@code null} if the alias can't be found.
     */
    @Override
    public PrivateKey getPrivateKey(String alias) {
        return extractInnerField(
                keyManager -> keyManager.getPrivateKey(alias),
                Objects::nonNull
        );
    }

    /**
     * Returns the first non-null certificate chain associated with the
     * given alias, or {@code null} if the alias can't be found.
     */
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return extractInnerField(
                keyManager -> keyManager.getCertificateChain(alias),
                chain -> chain != null && chain.length > 0
        );
    }

    /**
     * Get all matching aliases for authenticating the client side of a
     * secure socket, or {@code null} if there are no matches.
     */
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return getAliases(keyManager -> keyManager.getClientAliases(keyType, issuers));
    }

    /**
     * Get all matching aliases for authenticating the server side of a
     * secure socket, or {@code null} if there are no matches.
     */
    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return getAliases(keyManager -> keyManager.getServerAliases(keyType, issuers));
    }

    @Override
    public Map<String, X509ExtendedKeyManager> getInnerKeyManagers() {
        return Collections.unmodifiableMap(keyManagers);
    }

    @Override
    public Map<String, List<URI>> getIdentityRoute() {
        return preferredAliasToHost;
    }

}
