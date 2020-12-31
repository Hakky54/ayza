/*
 * Copyright 2019-2021 the original author or authors.
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

package nl.altindag.ssl.util;

import nl.altindag.ssl.exception.GenericSSLContextException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.List;

import static java.util.Objects.nonNull;

/**
 * @author Hakan Altindag
 */
public final class SSLContextUtils {

    private static final String DEFAULT_SSL_CONTEXT_PROTOCOL = "TLS";

    private SSLContextUtils() {
    }

    public static SSLContext createSslContext(List<? extends X509KeyManager> keyManagers, List<? extends X509TrustManager> trustManagers) {
        return createSslContext(keyManagers, trustManagers, null);
    }

    public static SSLContext createSslContext(List<? extends X509KeyManager> keyManagers, List<? extends X509TrustManager> trustManagers, SecureRandom secureRandom) {
        return createSslContext(keyManagers, trustManagers, secureRandom, DEFAULT_SSL_CONTEXT_PROTOCOL, (Provider) null);
    }

    public static SSLContext createSslContext(
            List<? extends X509KeyManager> keyManagers,
            List<? extends X509TrustManager> trustManagers,
            SecureRandom secureRandom,
            String sslContextProtocol,
            Provider securityProvider) {

        return createSslContext(
                !keyManagers.isEmpty() ? KeyManagerUtils.combine(keyManagers) : null,
                !trustManagers.isEmpty() ? TrustManagerUtils.combine(trustManagers) : null,
                secureRandom,
                sslContextProtocol,
                null,
                securityProvider
        );
    }

    public static SSLContext createSslContext(
            List<? extends X509KeyManager> keyManagers,
            List<? extends X509TrustManager> trustManagers,
            SecureRandom secureRandom,
            String sslContextProtocol,
            String securityProviderName) {

        return createSslContext(
                !keyManagers.isEmpty() ? KeyManagerUtils.combine(keyManagers) : null,
                !trustManagers.isEmpty() ? TrustManagerUtils.combine(trustManagers) : null,
                secureRandom,
                sslContextProtocol,
                securityProviderName,
                null
        );
    }

    public static SSLContext createSslContext(
            X509KeyManager keyManager,
            X509TrustManager trustManager,
            SecureRandom secureRandom,
            String sslContextProtocol,
            String securityProviderName,
            Provider securityProvider) {

        return createSslContext(
                keyManager != null ? KeyManagerUtils.toArray(keyManager) : null,
                trustManager != null ? TrustManagerUtils.toArray(trustManager) : null,
                secureRandom,
                sslContextProtocol,
                securityProviderName,
                securityProvider
        );
    }

    private static SSLContext createSslContext(
            X509KeyManager[] keyManagers,
            X509TrustManager[] trustManagers,
            SecureRandom secureRandom,
            String sslContextProtocol,
            String securityProviderName,
            Provider securityProvider) {

        try {
            SSLContext sslContext;
            if (nonNull(securityProvider)) {
                sslContext = SSLContext.getInstance(sslContextProtocol, securityProvider);
            } else if (nonNull(securityProviderName)) {
                sslContext = SSLContext.getInstance(sslContextProtocol, securityProviderName);
            } else {
                sslContext = SSLContext.getInstance(sslContextProtocol);
            }

            sslContext.init(keyManagers, trustManagers, secureRandom);
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException | NoSuchProviderException e) {
            throw new GenericSSLContextException(e);
        }
    }

}
