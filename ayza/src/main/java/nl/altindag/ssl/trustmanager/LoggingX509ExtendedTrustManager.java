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
package nl.altindag.ssl.trustmanager;

import nl.altindag.ssl.util.internal.HostUtils;
import nl.altindag.sude.Logger;
import nl.altindag.sude.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public final class LoggingX509ExtendedTrustManager extends DelegatingX509ExtendedTrustManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(LoggingX509ExtendedTrustManager.class);
    private static final Logger SUCCESS_LOGGER = LoggerFactory.getLogger(LoggingX509ExtendedTrustManager.class.getName() + ".success");
    private static final Logger EXCEPTION_LOGGER = LoggerFactory.getLogger(LoggingX509ExtendedTrustManager.class.getName() + ".exception");

    private static final String LOG_MESSAGE_TEMPLATE = "Validating the certificate chain of the %s%s with authentication type %s%s. See below for the full chain of the %s:\n%s";
    private static final String VALIDATION_PASSED_LOG_MESSAGE_TEMPLATE = "Successfully validated the %s%s with authentication type %s%s.";
    private static final String VALIDATION_FAILED_LOG_MESSAGE_TEMPLATE = "Failed validating the %s%s with authentication type %s%s.";

    public LoggingX509ExtendedTrustManager(X509ExtendedTrustManager trustManager) {
        super(trustManager);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(() -> super.checkClientTrusted(chain, authType), CounterParty.CLIENT, chain, authType, null, null);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkTrusted(() -> super.checkClientTrusted(chain, authType, socket), CounterParty.CLIENT, chain, authType, socket, null);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        checkTrusted(() -> super.checkClientTrusted(chain, authType, sslEngine), CounterParty.CLIENT, chain, authType, null, sslEngine);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(() -> super.checkServerTrusted(chain, authType), CounterParty.SERVER, chain, authType, null, null);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkTrusted(() -> super.checkServerTrusted(chain, authType, socket), CounterParty.SERVER, chain, authType, socket, null);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        checkTrusted(() -> super.checkServerTrusted(chain, authType, sslEngine), CounterParty.SERVER, chain, authType, null, sslEngine);
    }

    private static void checkTrusted(TrustManagerRunnable runnable,
                                     CounterParty counterParty,
                                     X509Certificate[] chain,
                                     String authType,
                                     Socket socket,
                                     SSLEngine sslEngine) throws CertificateException {

        String certificateChain = Arrays.toString(chain);

        Optional<String> classNameLogMessage = getClassnameOfEitherOrOther(socket, sslEngine)
                .map(className -> ", while also using the " + className);
        Optional<String> hostAndPortLogMessage = getHostAndPortOfEitherOrOther(socket, sslEngine)
                .map(hostAndPort -> "[" + hostAndPort + "]");

        String logMessage = String.format(LOG_MESSAGE_TEMPLATE, counterParty, hostAndPortLogMessage.orElse(""), authType, classNameLogMessage.orElse(""), counterParty, certificateChain);
        LOGGER.debug(logMessage);

        try {
            runnable.run();
            String okMessage = String.format(VALIDATION_PASSED_LOG_MESSAGE_TEMPLATE, counterParty, hostAndPortLogMessage.orElse(""), authType, classNameLogMessage.orElse(""));
            SUCCESS_LOGGER.debug(okMessage);
        } catch (CertificateException e) {
            String nokMessage = String.format(VALIDATION_FAILED_LOG_MESSAGE_TEMPLATE, counterParty, hostAndPortLogMessage.orElse(""), authType, classNameLogMessage.orElse(""));
            EXCEPTION_LOGGER.debug(nokMessage, e);
            throw e;
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

    static Optional<String> getHostAndPortOfEitherOrOther(Socket socket, SSLEngine sslEngine) {
        Map.Entry<String, Integer> hostToPort = null;
        if (socket != null) {
            hostToPort = HostUtils.extractHostAndPort(socket);
        }

        if (sslEngine != null) {
            hostToPort = HostUtils.extractHostAndPort(sslEngine);
        }

        if (hostToPort != null) {
            return Optional.of(String.join(":", hostToPort.getKey(), hostToPort.getValue().toString()));
        }

        return Optional.empty();
    }

    private enum CounterParty {
        SERVER, CLIENT;

        @Override
        public String toString() {
            return this.name().toLowerCase();
        }
    }

}
