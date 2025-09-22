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

import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.server.service.Server;
import nl.altindag.ssl.util.websocket.SimpleWebSocketSecureClientRunnable;
import nl.altindag.ssl.util.websocket.SimpleWebSocketServer;
import org.java_websocket.server.DefaultSSLWebSocketServerFactory;
import org.java_websocket.server.WebSocketServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Hakan Altindag
 */
class CertificateUtilsIT {

    private static Server serverOne;
    private static Server serverTwo;

    @BeforeAll
    static void setupServer() {
        SSLFactory sslFactoryForServerOne = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", "secret".toCharArray())
                .build();

        SSLFactory sslFactoryForServerTwo = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-two/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/server-two/truststore.jks", "secret".toCharArray())
                .build();

        serverOne = Server.createDefault(sslFactoryForServerOne, 8450);
        serverTwo = Server.createDefault(sslFactoryForServerTwo, 8451);
    }

    @AfterAll
    static void stopServer() {
        serverOne.stop();
        serverTwo.stop();
    }

    @Test
    void getRemoteCertificates() {
        Map<String, List<X509Certificate>> certificatesFromRemote = CertificateUtils.getCertificatesFromExternalSources("https://localhost:8450", "https://localhost:8451");

        assertThat(certificatesFromRemote)
                .isNotNull()
                .containsKeys("https://localhost:8450", "https://localhost:8451");

        assertThat(certificatesFromRemote.get("https://localhost:8450")).hasSizeGreaterThan(0);
        assertThat(certificatesFromRemote.get("https://localhost:8451")).hasSizeGreaterThan(0);
    }

    @Test
    void getRemoteCertificatesFromList() {
        List<String> urls = Arrays.asList("https://localhost:8450", "https://localhost:8451");

        Map<String, List<X509Certificate>> certificatesFromRemote = CertificateUtils.getCertificatesFromExternalSources(urls);

        assertThat(certificatesFromRemote)
                .isNotNull()
                .containsKeys("https://localhost:8450", "https://localhost:8451");

        assertThat(certificatesFromRemote.get("https://localhost:8450")).hasSizeGreaterThan(0);
        assertThat(certificatesFromRemote.get("https://localhost:8451")).hasSizeGreaterThan(0);
    }

    @Test
    void getRemoteCertificatesAsPem() {
        Map<String, List<String>> certificatesFromRemote = CertificateUtils.getCertificatesFromExternalSourcesAsPem("https://localhost:8450", "https://localhost:8451");

        assertThat(certificatesFromRemote)
                .isNotNull()
                .containsKeys("https://localhost:8450", "https://localhost:8451");

        assertThat(certificatesFromRemote.get("https://localhost:8450")).hasSizeGreaterThan(0);
        assertThat(certificatesFromRemote.get("https://localhost:8451")).hasSizeGreaterThan(0);
    }

    @Test
    void getRemoteCertificatesAsPemFromList() {
        List<String> urls = Arrays.asList("https://localhost:8450", "https://localhost:8451");

        Map<String, List<String>> certificatesFromRemote = CertificateUtils.getCertificatesFromExternalSourcesAsPem(urls);

        assertThat(certificatesFromRemote)
                .isNotNull()
                .containsKeys("https://localhost:8450", "https://localhost:8451");

        assertThat(certificatesFromRemote.get("https://localhost:8450")).hasSizeGreaterThan(0);
        assertThat(certificatesFromRemote.get("https://localhost:8451")).hasSizeGreaterThan(0);
    }

    @Test
    void getRemoteSelfSignedCertificate() {
        char[] keyStorePassword = "secret".toCharArray();
        SSLFactory sslFactoryForServerOne = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", keyStorePassword)
                .withProtocols("TLSv1.2")
                .build();

        Server server = Server.createDefault(sslFactoryForServerOne, 5002);

        Map<String, List<X509Certificate>> certificatesFromRemote = CertificateUtils.getCertificatesFromExternalSources("https://localhost:5002");

        server.stop();

        assertThat(certificatesFromRemote).containsKeys("https://localhost:5002");
        assertThat(certificatesFromRemote.get("https://localhost:5002")).hasSizeGreaterThan(0);
    }

    @Test
    void getRemoteCustomRootCaSignedCertificate() {
        char[] keyStorePassword = "secret".toCharArray();
        SSLFactory sslFactoryForServerOne = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-three/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/server-three/truststore.jks", keyStorePassword)
                .withProtocols("TLSv1.2")
                .build();

        Server server = Server.createDefault(sslFactoryForServerOne, 5001);

        Map<String, List<X509Certificate>> certificatesFromRemote = CertificateUtils.getCertificatesFromExternalSources("https://localhost:5001");

        server.stop();

        assertThat(certificatesFromRemote).containsKeys("https://localhost:5001");
        assertThat(certificatesFromRemote.get("https://localhost:5001")).hasSizeGreaterThan(0);
    }

    @Test
    void clearCertificateCollectorAfterExtractingCertificates() {
        char[] keyStorePassword = "secret".toCharArray();
        SSLFactory sslFactoryForServerOne = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-three/identity.jks", keyStorePassword)
                .withTrustMaterial("keystore/client-server/server-three/truststore.jks", keyStorePassword)
                .withProtocols("TLSv1.2")
                .build();

        Server server = Server.createDefault(sslFactoryForServerOne, 5000);

        CertificateExtractingClient client = CertificateExtractingClient.builder()
                .build();

        List<X509Certificate> certificates = client.get("https://localhost:5000");

        server.stop();

        assertThat(certificates).hasSizeGreaterThan(0);
        assertThat(client.getCertificatesCollector()).isEmpty();
    }

    @Test
    void getCertificatesFromWebSocket() throws Exception {
        SSLFactory sslFactory = SSLFactory.builder()
                .withIdentityMaterial("keystore/client-server/server-one/identity.jks", "secret".toCharArray())
                .withTrustMaterial("keystore/client-server/server-one/truststore.jks", "secret".toCharArray())
                .build();

        WebSocketServer server = new SimpleWebSocketServer(new InetSocketAddress("localhost", 9999));
        server.setWebSocketFactory(new DefaultSSLWebSocketServerFactory(sslFactory.getSslContext()));
        server.start();

        SimpleWebSocketSecureClientRunnable clientRunnable = new SimpleWebSocketSecureClientRunnable();
        CertificateExtractingClient extractingClient = CertificateExtractingClient.builder()
                .withClientRunnable(clientRunnable)
                .build();

        List<X509Certificate> certificates = extractingClient.get("wss://localhost:9999");
        assertThat(certificates).isNotEmpty();

        server.stop();
        clientRunnable.getWebSocketClient().closeBlocking();
    }

}
