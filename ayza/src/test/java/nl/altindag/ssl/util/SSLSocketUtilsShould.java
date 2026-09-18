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
package nl.altindag.ssl.util;

import nl.altindag.ssl.trustmanager.UnsafeX509ExtendedTrustManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocketFactory;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class SSLSocketUtilsShould {

    @Test
    void createSslSocketFactory() throws NoSuchAlgorithmException {
        SSLParameters sslParameters = spy(
                new SSLParameters(
                        new String[]{"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
                        new String[]{"TLSv1.2"}
                )
        );

        SSLSocketFactory socketFactory = SSLContext.getDefault().getSocketFactory();

        SSLSocketFactory victim = SSLSocketUtils.createSslSocketFactory(socketFactory, sslParameters);
        String[] defaultCipherSuites = victim.getDefaultCipherSuites();

        assertThat(defaultCipherSuites).containsExactly("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        verify(sslParameters, times(1)).getCipherSuites();
    }

    @Test
    void createSslSocketFactoryFromSslContext() throws NoSuchAlgorithmException {
        SSLParameters sslParameters = spy(
                new SSLParameters(
                        new String[]{"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
                        new String[]{"TLSv1.2"}
                )
        );

        SSLSocketFactory victim = SSLSocketUtils.createSslSocketFactory(SSLContext.getDefault(), sslParameters);
        String[] defaultCipherSuites = victim.getDefaultCipherSuites();

        assertThat(defaultCipherSuites).containsExactly("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        verify(sslParameters, times(1)).getCipherSuites();
    }

    @Test
    void createSslServerSocketFactory() throws NoSuchAlgorithmException {
        SSLParameters sslParameters = spy(
                new SSLParameters(
                        new String[]{"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
                        new String[]{"TLSv1.2"}
                )
        );

        SSLServerSocketFactory socketFactory = SSLContext.getDefault().getServerSocketFactory();

        SSLServerSocketFactory victim = SSLSocketUtils.createSslServerSocketFactory(socketFactory, sslParameters);
        String[] defaultCipherSuites = victim.getDefaultCipherSuites();

        assertThat(defaultCipherSuites).containsExactly("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        verify(sslParameters, times(1)).getCipherSuites();
    }

    @Test
    void createSslServerSocketFactoryFromSslContext() throws NoSuchAlgorithmException {
        SSLParameters sslParameters = spy(
                new SSLParameters(
                        new String[]{"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
                        new String[]{"TLSv1.2"}
                )
        );

        SSLServerSocketFactory victim = SSLSocketUtils.createSslServerSocketFactory(SSLContext.getDefault(), sslParameters);
        String[] defaultCipherSuites = victim.getDefaultCipherSuites();

        assertThat(defaultCipherSuites).containsExactly("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        verify(sslParameters, times(1)).getCipherSuites();
    }

    @Test
    void createUnsafeSslSocketFactoryWithUnsafeX509ExtendedTrustManager() {
        try (MockedStatic<UnsafeX509ExtendedTrustManager> mockedStatic = Mockito.mockStatic(UnsafeX509ExtendedTrustManager.class, InvocationOnMock::callRealMethod)) {
            SSLSocketFactory socketFactory = SSLSocketUtils.createUnsafeSslSocketFactory();
            assertThat(socketFactory).isNotNull();
            mockedStatic.verify(UnsafeX509ExtendedTrustManager::getInstance, times(1));
        }
    }

}
