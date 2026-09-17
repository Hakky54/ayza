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
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
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
class FenixSSLSocketFactoryShould {

    private final SSLParameters sslParameters = spy(
            new SSLParameters(
                    new String[] {"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"},
                    new String[] {"TLSv1.2"}
            )
    );

    private final SSLSocketFactory sslSocketFactory = mock(SSLSocketFactory.class);
    private final Consumer<SSLParameters> sslParametersEnhancer = mock(Consumer.class);

    private final FenixSSLSocketFactory victim = new FenixSSLSocketFactory(sslSocketFactory, sslParameters, sslParametersEnhancer);

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
    void createSocket() throws IOException {
        SSLSocket mockedSslSocket = mock(SSLSocket.class);
        doReturn(mockedSslSocket).when(sslSocketFactory).createSocket();

        try(MockedStatic<SSLParameters> mockedStatic = mockStatic(SSLParameters.class)) {
            Socket socket = victim.createSocket();

            assertThat(socket).isNotNull();
            verify(sslSocketFactory, times(1)).createSocket();
            verify(mockedSslSocket, times(1)).setSSLParameters(any());

            mockedStatic.verify(() -> SSLParametersUtils.copy(sslParameters), times(1));
        }
    }

    @Test
    void createSocketWithHotSwappableSslParameters() throws IOException {
        SSLSocket mockedSslSocket = mock(SSLSocket.class);
        doReturn(mockedSslSocket).when(sslSocketFactory).createSocket();

        try (MockedStatic<SSLParameters> mockedStatic = mockStatic(SSLParameters.class)) {
            FenixSSLSocketFactory victim = new FenixSSLSocketFactory(sslSocketFactory, SSLParametersUtils.createSwappableSslParameters(sslParameters), sslParametersEnhancer);
            Socket socket = victim.createSocket();

            assertThat(socket).isNotNull().isInstanceOf(FenixSSLSocket.class);
            verify(sslSocketFactory, times(1)).createSocket();
            verify(mockedSslSocket, times(1)).setSSLParameters(any());

            mockedStatic.verify(() -> SSLParametersUtils.copy(sslParameters), times(1));
        }
    }

    @Test
    void createSocketDoesNotUseSslParametersWhenInnerSslSocketFactoryReturnsSocket() throws IOException {
        Socket mockedSocket = mock(Socket.class);

        doReturn(mockedSocket).when(sslSocketFactory).createSocket();

        Socket socket = victim.createSocket();

        assertThat(socket).isNotNull();
        verify(sslSocketFactory, times(1)).createSocket();
        verifyNoInteractions(mockedSocket);
    }

    @Test
    void createSocketWithSocketInputStreamAutoClosable() throws IOException {
        Socket baseSocket = mock(SSLSocket.class);
        SSLSocket mockedSslSocket = mock(SSLSocket.class);
        InputStream inputStream = new ByteArrayInputStream(new byte[]{});

        doReturn(mockedSslSocket)
                .when(sslSocketFactory).createSocket(any(Socket.class), any(InputStream.class), anyBoolean());

        try(MockedStatic<SSLParameters> mockedStatic = mockStatic(SSLParameters.class)) {
            Socket socket = victim.createSocket(baseSocket, inputStream, true);

            assertThat(socket).isNotNull();
            verify(sslSocketFactory, times(1)).createSocket(baseSocket, inputStream, true);
            verify(mockedSslSocket, times(1)).setSSLParameters(any());

            mockedStatic.verify(() -> SSLParametersUtils.copy(sslParameters), times(1));
        }
    }

    @Test
    void createSocketWithSocketHostPortAutoClosable() throws IOException {
        Socket baseSocket = mock(SSLSocket.class);
        SSLSocket mockedSslSocket = mock(SSLSocket.class);

        doReturn(mockedSslSocket)
                .when(sslSocketFactory).createSocket(any(Socket.class), anyString(), anyInt(), anyBoolean());

        try(MockedStatic<SSLParameters> mockedStatic = mockStatic(SSLParameters.class)) {
            Socket socket = victim.createSocket(baseSocket, "localhost", 8443, true);

            assertThat(socket).isNotNull();
            verify(sslSocketFactory, times(1)).createSocket(baseSocket, "localhost", 8443, true);
            verify(mockedSslSocket, times(1)).setSSLParameters(any());

            mockedStatic.verify(() -> SSLParametersUtils.copy(sslParameters), times(1));
        }
    }

    @Test
    void createSocketWithHostPort() throws IOException {
        SSLSocket mockedSslSocket = mock(SSLSocket.class);

        doReturn(mockedSslSocket)
                .when(sslSocketFactory).createSocket(anyString(), anyInt());

        try(MockedStatic<SSLParameters> mockedStatic = mockStatic(SSLParameters.class)) {
            Socket socket = victim.createSocket("localhost", 8443);

            assertThat(socket).isNotNull();
            verify(sslSocketFactory, times(1)).createSocket("localhost", 8443);
            verify(mockedSslSocket, times(1)).setSSLParameters(any());

            mockedStatic.verify(() -> SSLParametersUtils.copy(sslParameters), times(1));
        }
    }

    @Test
    void createSocketWithHostPortLocalAddressLocalPort() throws IOException {
        SSLSocket mockedSslSocket = mock(SSLSocket.class);

        doReturn(mockedSslSocket)
                .when(sslSocketFactory).createSocket(anyString(), anyInt(), any(InetAddress.class), anyInt());

        try(MockedStatic<SSLParameters> mockedStatic = mockStatic(SSLParameters.class)) {
            Socket socket = victim.createSocket("localhost", 8443, InetAddress.getLocalHost(), 1234);

            assertThat(socket).isNotNull();
            verify(sslSocketFactory, times(1)).createSocket("localhost", 8443, InetAddress.getLocalHost(), 1234);
            verify(mockedSslSocket, times(1)).setSSLParameters(any());

            mockedStatic.verify(() -> SSLParametersUtils.copy(sslParameters), times(1));
        }
    }

    @Test
    void createSocketWithAddressPort() throws IOException {
        SSLSocket mockedSslSocket = mock(SSLSocket.class);

        doReturn(mockedSslSocket)
                .when(sslSocketFactory).createSocket(any(InetAddress.class), anyInt());

        try(MockedStatic<SSLParameters> mockedStatic = mockStatic(SSLParameters.class)) {
            Socket socket = victim.createSocket(InetAddress.getLocalHost(), 1234);

            assertThat(socket).isNotNull();
            verify(sslSocketFactory, times(1)).createSocket(InetAddress.getLocalHost(), 1234);
            verify(mockedSslSocket, times(1)).setSSLParameters(any());

            mockedStatic.verify(() -> SSLParametersUtils.copy(sslParameters), times(1));
        }
    }

    @Test
    void createSocketWithAddressPortLocalAddressPort() throws IOException {
        SSLSocket mockedSslSocket = mock(SSLSocket.class);

        doReturn(mockedSslSocket)
                .when(sslSocketFactory).createSocket(any(InetAddress.class), anyInt(), any(InetAddress.class), anyInt());

        try(MockedStatic<SSLParameters> mockedStatic = mockStatic(SSLParameters.class)) {
            Socket socket = victim.createSocket(InetAddress.getLocalHost(), 1234, InetAddress.getLocalHost(), 4321);

            assertThat(socket).isNotNull();
            verify(sslSocketFactory, times(1)).createSocket(InetAddress.getLocalHost(), 1234, InetAddress.getLocalHost(), 4321);
            verify(mockedSslSocket, times(1)).setSSLParameters(any());

            mockedStatic.verify(() -> SSLParametersUtils.copy(sslParameters), times(1));
        }
    }

}
