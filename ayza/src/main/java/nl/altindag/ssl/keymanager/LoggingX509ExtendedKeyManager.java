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

import nl.altindag.sude.Logger;
import nl.altindag.sude.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public class LoggingX509ExtendedKeyManager extends DelegatingX509ExtendedKeyManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoggingX509ExtendedKeyManager.class);
    private static final String CHOOSE_ALIAS_LOG_MESSAGE_TEMPLATE = "Attempting to find a %s alias for key types %s%s.%s";
    private static final String FOUND_ALIAS_LOG_MESSAGE_TEMPLATE = "Found the following %s aliases [%s] for key types %s%s.%s";

    public LoggingX509ExtendedKeyManager(X509ExtendedKeyManager keyManager) {
        super(keyManager);
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        logAttemptOfChoosingAlias(ServerOrClient.CLIENT, keyType, issuers, socket, null);

        String alias = super.chooseClientAlias(keyType, issuers, socket);
        logAliasIfPresent(ServerOrClient.CLIENT, alias, keyType, issuers, socket, null);

        return alias;
    }

    @Override
    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine sslEngine) {
        logAttemptOfChoosingAlias(ServerOrClient.CLIENT, keyTypes, issuers, null, sslEngine);

        String alias = super.chooseEngineClientAlias(keyTypes, issuers, sslEngine);
        logAliasIfPresent(ServerOrClient.CLIENT, alias, keyTypes, issuers, null, sslEngine);

        return alias;
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        logAttemptOfChoosingAlias(ServerOrClient.SERVER, keyType, issuers, socket, null);

        String alias = super.chooseServerAlias(keyType, issuers, socket);
        logAliasIfPresent(ServerOrClient.SERVER, alias, keyType, issuers, socket, null);

        return alias;
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine sslEngine) {
        logAttemptOfChoosingAlias(ServerOrClient.SERVER, new String[]{keyType}, issuers, null, sslEngine);

        String alias = super.chooseEngineServerAlias(keyType, issuers, sslEngine);
        logAliasIfPresent(ServerOrClient.SERVER, alias, keyType, issuers, null, sslEngine);

        return alias;
    }

    private void logAttemptOfChoosingAlias(ServerOrClient serverOrClient, String keyType, Principal[] issuers, Socket socket, SSLEngine sslEngine) {
        logAttemptOfChoosingAlias(serverOrClient, new String[]{keyType}, issuers, socket, sslEngine);
    }

    private void logAttemptOfChoosingAlias(ServerOrClient serverOrClient, String[] keyTypes, Principal[] issuers, Socket socket, SSLEngine sslEngine) {
        String combinedKeyTypes = Arrays.toString(keyTypes);
        String issuersLogMessage = getIssuersLogMessage(issuers);
        String classNameLogMessage = getClassNameLogMessage(socket, sslEngine);

        String logMessage = String.format(CHOOSE_ALIAS_LOG_MESSAGE_TEMPLATE, serverOrClient, combinedKeyTypes, classNameLogMessage, issuersLogMessage);
        LOGGER.debug(logMessage);
    }

    private void logAliasIfPresent(ServerOrClient serverOrClient, String alias, String keyType, Principal[] issuers, Socket socket, SSLEngine sslEngine) {
        logAliasIfPresent(serverOrClient, alias, new String[]{keyType}, issuers, socket, sslEngine);
    }

    private void logAliasIfPresent(ServerOrClient serverOrClient, String alias, String[] keyTypes, Principal[] issuers, Socket socket, SSLEngine sslEngine) {
        if (alias != null) {
            String combinedKeyTypes = Arrays.toString(keyTypes);
            String issuersLogMessage = getIssuersLogMessage(issuers);
            String classNameLogMessage = getClassNameLogMessage(socket, sslEngine);

            String logMessage = String.format(FOUND_ALIAS_LOG_MESSAGE_TEMPLATE, serverOrClient, alias, combinedKeyTypes, classNameLogMessage, issuersLogMessage);
            LOGGER.debug(logMessage);
        }
    }

    static Optional<String> getClassnameOfEitherOrOther(Socket socket, SSLEngine sslEngine) {
        if (socket != null) {
            return Optional.of(Socket.class.getSimpleName());
        }

        if (sslEngine != null) {
            return Optional.of(SSLEngine.class.getSimpleName());
        }

        return Optional.empty();
    }

    private static String getClassNameLogMessage(Socket socket, SSLEngine sslEngine) {
        return getClassnameOfEitherOrOther(socket, sslEngine)
                .map(className -> ", while also using the " + className + "")
                .orElse("");
    }

    private static String getIssuersLogMessage(Principal[] issuers) {
        return Optional.ofNullable(issuers)
                .filter(principals -> principals.length > 0)
                .map(Arrays::toString)
                .map(combinedIssuers -> String.format(" See below for list of the issuers:%n%s", combinedIssuers))
                .orElse("");
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        LOGGER.debug(String.format("Attempting to get the private key for the alias: %s", alias));

        PrivateKey privateKey = super.getPrivateKey(alias);
        if (privateKey != null) {
            String logMessage = String.format("Found a private key for the alias: %s", alias);
            LOGGER.debug(logMessage);
        }
        return privateKey;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        LOGGER.debug(String.format("Attempting to get the certificate chain for the alias: %s", alias));

        X509Certificate[] certificateChain = super.getCertificateChain(alias);
        if (certificateChain != null && certificateChain.length > 0) {
            String combinedCertificateChain = Arrays.toString(certificateChain);
            String logMessage = String.format("Found the certificate chain with a size of %d for the alias: %s. See below for the full chain:%n%s",
                    certificateChain.length, alias, combinedCertificateChain);
            LOGGER.debug(logMessage);
        }

        return certificateChain;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        logAttemptOfChoosingAlias(ServerOrClient.CLIENT, keyType, issuers, null, null);

        String[] clientAliases = super.getClientAliases(keyType, issuers);
        logAliasIfPresent(ServerOrClient.CLIENT, clientAliases, keyType, issuers);

        return clientAliases;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        logAttemptOfChoosingAlias(ServerOrClient.SERVER, keyType, issuers, null, null);

        String[] serverAliases = super.getServerAliases(keyType, issuers);
        logAliasIfPresent(ServerOrClient.SERVER, serverAliases, keyType, issuers);

        return serverAliases;
    }

    private void logAliasIfPresent(ServerOrClient serverOrClient, String[] aliases, String keyType, Principal[] issuers) {
        if (aliases != null && aliases.length > 0) {
            logAliasIfPresent(serverOrClient, String.join(", ", aliases), new String[]{keyType}, issuers, null, null);
        }
    }

    private enum ServerOrClient {
        SERVER, CLIENT;

        @Override
        public String toString() {
            return this.name().toLowerCase();
        }
    }

}
