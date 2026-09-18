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
package nl.altindag.ssl.socket;

import nl.altindag.ssl.util.SSLParametersUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class FenixSSLServerSocketFactoryShould {

    private final SSLParameters sslParameters = spy(
            new SSLParameters(
                    new String[] {"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
                    new String[] {"TLSv1.2"}
            )
    );

    private final SSLServerSocketFactory sslServerSocketFactory = mock(SSLServerSocketFactory.class);
    private final Consumer<SSLParameters> sslParametersEnhancer = mock(Consumer.class);

    private final FenixSSLServerSocketFactory victim = new FenixSSLServerSocketFactory(sslServerSocketFactory, sslParameters, sslParametersEnhancer);

    @Test
    void returnDefaultCipherSuites() {
        String[] defaultCipherSuites = victim.getDefaultCipherSuites();

        assertThat(defaultCipherSuites).containsExactly("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        verify(sslParameters, times(1)).getCipherSuites();
    }

    @Test
    void returnSupportedCipherSuites() {
        String[] supportedCipherSuites = victim.getSupportedCipherSuites();

        assertThat(supportedCipherSuites).containsExactly("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
        verify(sslParameters, times(1)).getCipherSuites();
    }

    @Test
    void createServerSocket() throws IOException {
        SSLServerSocket mockedSslServerSocket = mock(SSLServerSocket.class);

        doReturn(mockedSslServerSocket).when(sslServerSocketFactory).createServerSocket();

        try(MockedStatic<SSLParameters> mockedStatic = mockStatic(SSLParameters.class)) {
            ServerSocket serverSocket = victim.createServerSocket();

            assertThat(serverSocket).isNotNull();
            verify(sslServerSocketFactory, times(1)).createServerSocket();
            verify(mockedSslServerSocket, times(1)).setSSLParameters(any());

            mockedStatic.verify(() -> SSLParametersUtils.copy(sslParameters), times(1));
        }
    }

    @Test
    void createServerSocketWithHotSwappableSslParameters() throws IOException {
        SSLServerSocket mockedSslServerSocket = mock(SSLServerSocket.class);
        doReturn(mockedSslServerSocket).when(sslServerSocketFactory).createServerSocket();

        try (MockedStatic<SSLParameters> mockedStatic = mockStatic(SSLParameters.class)) {
            FenixSSLServerSocketFactory victim = new FenixSSLServerSocketFactory(sslServerSocketFactory, SSLParametersUtils.createSwappableSslParameters(sslParameters), sslParametersEnhancer);
            ServerSocket socket = victim.createServerSocket();

            assertThat(socket).isNotNull().isInstanceOf(FenixSSLServerSocket.class);
            verify(sslServerSocketFactory, times(1)).createServerSocket();
            verify(mockedSslServerSocket, times(1)).setSSLParameters(any());

            mockedStatic.verify(() -> SSLParametersUtils.copy(sslParameters), times(1));
        }
    }

    @Test
    void createServerSocketDoesNotUseSslParametersWhenInnerSslServerSocketFactoryReturnsServerSocket() throws IOException {
        ServerSocket mockedServerSocket = mock(ServerSocket.class);

        doReturn(mockedServerSocket).when(sslServerSocketFactory).createServerSocket();

        ServerSocket serverSocket = victim.createServerSocket();

        assertThat(serverSocket).isNotNull();
        verify(sslServerSocketFactory, times(1)).createServerSocket();
        verifyNoInteractions(mockedServerSocket);
    }

    @Test
    void createServerSocketWithPort() throws IOException {
        SSLServerSocket mockedSslServerSocket = mock(SSLServerSocket.class);

        doReturn(mockedSslServerSocket)
                .when(sslServerSocketFactory).createServerSocket(anyInt());

        try(MockedStatic<SSLParameters> mockedStatic = mockStatic(SSLParameters.class)) {
            ServerSocket serverSocket = victim.createServerSocket(8443);

            assertThat(serverSocket).isNotNull();
            verify(sslServerSocketFactory, times(1)).createServerSocket(8443);
            verify(mockedSslServerSocket, times(1)).setSSLParameters(any());

            mockedStatic.verify(() -> SSLParametersUtils.copy(sslParameters), times(1));
        }
    }

    @Test
    void createServerSocketWithPortBacklog() throws IOException {
        SSLServerSocket mockedSslServerSocket = mock(SSLServerSocket.class);

        doReturn(mockedSslServerSocket)
                .when(sslServerSocketFactory).createServerSocket(anyInt(), anyInt());

        try(MockedStatic<SSLParameters> mockedStatic = mockStatic(SSLParameters.class)) {
            ServerSocket serverSocket = victim.createServerSocket(8443, 50);

            assertThat(serverSocket).isNotNull();
            verify(sslServerSocketFactory, times(1)).createServerSocket(8443, 50);
            verify(mockedSslServerSocket, times(1)).setSSLParameters(any());

            mockedStatic.verify(() -> SSLParametersUtils.copy(sslParameters), times(1));
        }
    }

    @Test
    void createServerSocketWithPortBacklogIfAddress() throws IOException {
        SSLServerSocket mockedSslServerSocket = mock(SSLServerSocket.class);

        doReturn(mockedSslServerSocket)
                .when(sslServerSocketFactory).createServerSocket(anyInt(), anyInt(), any(InetAddress.class));

        try(MockedStatic<SSLParameters> mockedStatic = mockStatic(SSLParameters.class)) {
            ServerSocket serverSocket = victim.createServerSocket(8443, 50, InetAddress.getLocalHost());

            assertThat(serverSocket).isNotNull();
            verify(sslServerSocketFactory, times(1)).createServerSocket(8443, 50, InetAddress.getLocalHost());
            verify(mockedSslServerSocket, times(1)).setSSLParameters(any());

            mockedStatic.verify(() -> SSLParametersUtils.copy(sslParameters), times(1));
        }
    }

}
