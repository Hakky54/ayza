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

import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.exception.GenericIOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLException;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class CertificateExtractingClientShould {

    @Test
    void getRootCaIfPossibleReturnsJdkTrustedCaCertificateWhenNoAuthorityInfoAccessExtensionIsPresent() {
        List<X509Certificate> certificates = CertificateUtils.getCertificatesFromExternalSource("https://www.reddit.com/");

        try (MockedStatic<CertificateExtractingClient> mockedStatic = mockStatic(CertificateExtractingClient.class, invocation -> {
            Method method = invocation.getMethod();
            if ("getRootCaFromAuthorityInfoAccessExtensionIfPresent".equals(method.getName())) {
                return Collections.emptyList();
            } else {
                return invocation.callRealMethod();
            }
        })) {
            CertificateExtractingClient victim = spy(CertificateExtractingClient.getInstance());

            X509Certificate certificate = certificates.get(certificates.size() - 1);
            List<X509Certificate> rootCaCertificate = victim.getRootCaIfPossible(certificate);
            assertThat(rootCaCertificate).isNotEmpty();

            verify(victim, times(1)).getRootCaFromJdkTrustedCertificates(certificate);
        }
    }

    @Test
    void getRootCaIfPossibleReturnsEmptyListWhenNoAuthorityInfoAccessExtensionIsPresentAndNoMatching() {
        List<X509Certificate> certificates = CertificateUtils.getCertificatesFromExternalSource("https://www.reddit.com/");

        try (MockedStatic<CertificateExtractingClient> mockedStatic = mockStatic(CertificateExtractingClient.class, invocation -> {
            Method method = invocation.getMethod();
            if ("getRootCaFromAuthorityInfoAccessExtensionIfPresent".equals(method.getName()) || "getRootCaFromJdkTrustedCertificates".equals(method.getName())) {
                return Collections.emptyList();
            } else {
                return invocation.callRealMethod();
            }
        })) {
            CertificateExtractingClient victim = spy(CertificateExtractingClient.getInstance());

            doReturn(Collections.emptyList())
                    .when(victim)
                    .getRootCaFromJdkTrustedCertificates(any(X509Certificate.class));

            X509Certificate certificate = certificates.get(certificates.size() - 1);
            List<X509Certificate> rootCaCertificate = victim.getRootCaIfPossible(certificate);
            assertThat(rootCaCertificate).isEmpty();

            verify(victim, times(1)).getRootCaFromAuthorityInfoAccessExtensionIfPresent(certificate);
            verify(victim, times(1)).getRootCaFromJdkTrustedCertificates(certificate);
        }
    }

    @Test
    void rootCaIsNotResolvedWhenDisabled() {
        CertificateExtractingClient client = spy(CertificateExtractingClient.builder()
                .withResolvedRootCa(false)
                .build());

        client.get("https://www.reddit.com/");

        verify(client, times(0)).getRootCaFromChainIfPossible(anyList());
    }

    @Test
    void getRootCaFromChainIfPossibleReturnsEmptyListWhenNoCertificatesHaveBeenProvided() {
        List<X509Certificate> rootCa = CertificateExtractingClient.getInstance().getRootCaFromChainIfPossible(Collections.emptyList());
        assertThat(rootCa).isEmpty();
    }

    @Test
    void getRootCaFromAuthorityInfoAccessExtensionIfPresentReturnsEmptyListWhenCertificateIsNotInstanceOfX509CertImpl() {
        List<X509Certificate> rootCa = CertificateExtractingClient.getInstance().getRootCaFromAuthorityInfoAccessExtensionIfPresent(mock(X509Certificate.class));
        assertThat(rootCa).isEmpty();
    }

    @Test
    void returnEmptyListOfCertificatesWhenGetCertificatesFromRemoteFileFails() {
        CertificateExtractingClient victim = CertificateExtractingClient.getInstance();

        try (LogCaptor logCaptor = LogCaptor.forClass(CertificateExtractingClient.class);
             MockedStatic<URI> uriMockedStatic = mockStatic(URI.class, invocationOnMock -> {
                 throw new MalformedURLException("KABOOM!!!");
             })) {
            List<X509Certificate> certificates = victim.getCertificatesFromRemoteFile("https:google.com", null);
            assertThat(certificates).isEmpty();
            assertThat(logCaptor.getDebugLogs()).contains("Skipped getting certificate from remote file while using the following location [https:google.com]");
        }
    }

    @Test
    void timeoutIfServerFailsToRespondInTimeAndReturnsEmptyListOfCertificatesWhenExceptionHasCauseOfSocketTimeoutException() throws IOException {
        LogCaptor logCaptor = LogCaptor.forClass(CertificateExtractingClient.class);

        CertificateExtractingClient victim = spy(CertificateExtractingClient.builder().withTimeout(100).build());

        IOException ioException = new SSLException(new SocketTimeoutException("read timeout"));
        HttpsURLConnection connection = spy((HttpsURLConnection) new URL("https://google.com").openConnection());

        when(victim.createConnection(new URL("https://google.com"))).thenReturn(connection);
        doThrow(ioException).when(connection).connect();

        List<X509Certificate> certificates = victim.get("https://google.com");
        assertThat(certificates).isEmpty();
        assertThat(logCaptor.getDebugLogs()).contains("The client didn't get a respond within the configured time-out of [100] milliseconds from: [https://google.com]");
    }

    @Test
    void timeoutIfServerFailsToRespondInTimeAndReturnsEmptyListOfCertificatesWhenExceptionIsInstanceOfSocketTimeoutException() throws IOException {
        LogCaptor logCaptor = LogCaptor.forClass(CertificateExtractingClient.class);

        CertificateExtractingClient victim = spy(CertificateExtractingClient.builder().withTimeout(100).build());

        IOException ioException = new SocketTimeoutException("read timeout");
        HttpsURLConnection connection = spy((HttpsURLConnection) new URL("https://google.com").openConnection());

        when(victim.createConnection(new URL("https://google.com"))).thenReturn(connection);
        doThrow(ioException).when(connection).connect();

        List<X509Certificate> certificates = victim.get("https://google.com");
        assertThat(certificates).isEmpty();
        assertThat(logCaptor.getDebugLogs()).contains("The client didn't get a respond within the configured time-out of [100] milliseconds from: [https://google.com]");
    }

    @Test
    void reUseExistingUnsafeSslSocketFactory() throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException {
        String url = "https://cacerts.digicert.com/DigiCertGlobalRootCA.crt";
        X509Certificate intermediateCertificate = mock(X509Certificate.class);
        doNothing().when(intermediateCertificate).verify(any());

        List<X509Certificate> certificatesFromRemoteFile = CertificateExtractingClient.getInstance().getCertificatesFromRemoteFile(url, intermediateCertificate);
        assertThat(certificatesFromRemoteFile).isNotEmpty();
    }

    @Test
    void extractCertificatesWithProxyAndAuthentication() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        CertificateExtractingClient certificateExtractingClientWithoutProxy = CertificateExtractingClient.getInstance();
        List<X509Certificate> certificates = certificateExtractingClientWithoutProxy.get("https://google.com");
        assertThat(certificates).isNotEmpty();

        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("my-custom-host", 8081));
        CertificateExtractingClient certificateExtractingClientWithProxy = CertificateExtractingClient.builder()
                .withProxy(proxy)
                .withResolvedRootCa(true)
                .build();

        assertThatThrownBy(() -> certificateExtractingClientWithProxy.get("https://google.com"))
                .isInstanceOf(GenericIOException.class)
                .hasMessage("Failed getting certificate from: [https://google.com]")
                .hasRootCauseInstanceOf(UnknownHostException.class)
                .hasRootCauseMessage("my-custom-host");

        try (MockedStatic<Authenticator> mockedAuthenticator = mockStatic(Authenticator.class, InvocationOnMock::callRealMethod)) {
            ArgumentCaptor<Authenticator> authenticatorCaptor = ArgumentCaptor.forClass(Authenticator.class);

            PasswordAuthentication passwordAuthentication = new PasswordAuthentication("foo", "bar".toCharArray());
            CertificateExtractingClient certificateExtractingClientWithProxyAndAuthentication = CertificateExtractingClient.builder()
                    .withProxy(proxy)
                    .withPasswordAuthentication(passwordAuthentication)
                    .withResolvedRootCa(true)
                    .build();

            assertThatThrownBy(() -> certificateExtractingClientWithProxyAndAuthentication.get("https://google.com"))
                    .isInstanceOf(GenericIOException.class)
                    .hasMessage("Failed getting certificate from: [https://google.com]")
                    .hasRootCauseInstanceOf(UnknownHostException.class)
                    .hasRootCauseMessage("my-custom-host");

            mockedAuthenticator.verify(() -> Authenticator.setDefault(authenticatorCaptor.capture()), times(1));

            Authenticator authenticator = authenticatorCaptor.getValue();
            Method getPasswordAuthenticationMethod = authenticator.getClass().getDeclaredMethod("getPasswordAuthentication");
            Object pa = getPasswordAuthenticationMethod.invoke(authenticator);

            assertThat(pa).hasSameClassAs(passwordAuthentication);
        }
    }

    @Test
    void extractSiblingCertificates() {
        List<X509Certificate> certificates = CertificateExtractingClient.getInstance().get("https://www.facebook.com/");
        Map<String, List<X509Certificate>> siblingCertificates = CertificateExtractingClient.getInstance().getSiblings(certificates);
        assertThat(siblingCertificates).isNotEmpty();
    }


}
