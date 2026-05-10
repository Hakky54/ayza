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

import nl.altindag.ssl.sslparameters.HotSwappableSSLParameters;
import nl.altindag.ssl.util.SSLParametersUtils;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import static nl.altindag.laleler.ValidationUtils.GENERIC_EXCEPTION_MESSAGE;
import static nl.altindag.laleler.ValidationUtils.requireNotNull;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.SSLSocketUtils SSLSocketUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 *
 * @author Hakan Altindag
 */
public final class FenixSSLSocketFactory extends SSLSocketFactory {

    private final SSLSocketFactory sslSocketFactory;
    private final SSLParameters sslParameters;

    public FenixSSLSocketFactory(SSLSocketFactory sslSocketFactory, SSLParameters sslParameters) {
        this.sslSocketFactory = requireNotNull(sslSocketFactory, GENERIC_EXCEPTION_MESSAGE.apply("SSLSocketFactory"));
        this.sslParameters = requireNotNull(sslParameters, GENERIC_EXCEPTION_MESSAGE.apply("SSLParameters"));
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return sslParameters.getCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return sslParameters.getCipherSuites();
    }

    @Override
    public Socket createSocket() throws IOException {
        Socket socket = sslSocketFactory.createSocket();
        return withSslParameters(socket);
    }

    @Override
    public Socket createSocket(Socket socket, InputStream inputStream, boolean autoClosable) throws IOException {
        Socket newSocket = sslSocketFactory.createSocket(socket, inputStream, autoClosable);
        return withSslParameters(newSocket);
    }

    @Override
    public Socket createSocket(Socket socket, String host, int port, boolean autoClosable) throws IOException {
        Socket newSocket = sslSocketFactory.createSocket(socket, host, port, autoClosable);
        return withSslParameters(newSocket);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        Socket socket = sslSocketFactory.createSocket(host, port);
        return withSslParameters(socket);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localAddress, int localPort) throws IOException, UnknownHostException {
        Socket socket = sslSocketFactory.createSocket(host, port, localAddress, localPort);
        return withSslParameters(socket);
    }

    @Override
    public Socket createSocket(InetAddress address, int port) throws IOException {
        Socket socket = sslSocketFactory.createSocket(address, port);
        return withSslParameters(socket);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        Socket socket = sslSocketFactory.createSocket(address, port, localAddress, localPort);
        return withSslParameters(socket);
    }

    private Socket withSslParameters(Socket socket) {
        if (socket instanceof SSLSocket) {
            SSLSocket sslSocket = (SSLSocket) socket;
            sslSocket.setSSLParameters(SSLParametersUtils.copy(sslParameters));

            if (sslParameters instanceof HotSwappableSSLParameters) {
                return new FenixSSLSocket(sslSocket, sslParameters);
            }
        }
        return socket;
    }

}
