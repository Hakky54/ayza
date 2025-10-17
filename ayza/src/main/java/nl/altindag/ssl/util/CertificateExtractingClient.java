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
import nl.altindag.ssl.exception.GenericIOException;
import nl.altindag.ssl.model.ClientConfig;
import nl.altindag.sude.Logger;
import nl.altindag.sude.LoggerFactory;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static nl.altindag.ssl.util.internal.CollectorsUtils.toUnmodifiableList;

/**
 * @author Hakan Altindag
 */
public class CertificateExtractingClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateExtractingClient.class);
    private static final Pattern CA_ISSUERS_AUTHORITY_INFO_ACCESS = Pattern.compile("(?s)^AuthorityInfoAccess\\h+\\[\\R\\s*\\[\\R.*?accessMethod:\\h+caIssuers\\R\\h*accessLocation: URIName:\\h+(https?://\\S+)", Pattern.MULTILINE);
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(1);

    private static CertificateExtractingClient instance;

    private final boolean shouldResolveRootCa;
    private final Proxy proxy;
    private final SSLFactory sslFactoryForCertificateCapturing;
    private final SSLFactory unsafeSslFactory;
    private final SSLSocketFactory unsafeSslSocketFactory;
    private final SSLSocketFactory certificateCapturingSslSocketFactory;
    private final List<X509Certificate> certificatesCollector;
    private final Duration timeout;

    private final ClientConfig clientConfig;
    private final ClientRunnable clientRunnable;

    private CertificateExtractingClient(boolean shouldResolveRootCa,
                                        Proxy proxy,
                                        PasswordAuthentication passwordAuthentication,
                                        Duration timeout,
                                        ClientRunnable clientRunnable) {

        this.shouldResolveRootCa = shouldResolveRootCa;
        this.proxy = proxy;
        this.timeout = timeout;
        this.clientRunnable = clientRunnable;
        if (passwordAuthentication != null) {
            Authenticator authenticator = AuthenticatorUtils.create(passwordAuthentication);
            Authenticator.setDefault(authenticator);
        }

        certificatesCollector = new CopyOnWriteArrayList<>();

        X509ExtendedTrustManager certificateCapturingTrustManager = TrustManagerUtils.createCertificateCapturingTrustManager(certificatesCollector);

        sslFactoryForCertificateCapturing = SSLFactory.builder()
                .withTrustMaterial(certificateCapturingTrustManager)
                .build();

        unsafeSslFactory = SSLFactory.builder()
                .withUnsafeTrustMaterial()
                .build();

        certificateCapturingSslSocketFactory = sslFactoryForCertificateCapturing.getSslSocketFactory();
        unsafeSslSocketFactory = unsafeSslFactory.getSslSocketFactory();
        clientConfig = new ClientConfig(sslFactoryForCertificateCapturing, proxy, passwordAuthentication, timeout);
    }

    static CertificateExtractingClient getInstance() {
        if (instance == null) {
            instance = new CertificateExtractingClient(true, null, null, DEFAULT_TIMEOUT, null);
        }
        return instance;
    }

    public List<X509Certificate> get(String url) {
        try {
            URI uri = URI.create(url);
            if (clientRunnable != null) {
                clientRunnable.run(clientConfig, uri);
            } else if ("https".equalsIgnoreCase(uri.getScheme())) {
                HttpsURLConnection connection = (HttpsURLConnection) createConnection(uri.toURL());
                connection.setSSLSocketFactory(certificateCapturingSslSocketFactory);
                connection.setConnectTimeout((int) timeout.toMillis());
                connection.setReadTimeout((int) timeout.toMillis());
                connection.connect();
                connection.disconnect();
            } else {
                return Collections.emptyList();
            }

            List<X509Certificate> resolvedRootCa = shouldResolveRootCa? getRootCaFromChainIfPossible(certificatesCollector) : Collections.emptyList();
            return Stream.of(certificatesCollector, resolvedRootCa)
                    .flatMap(Collection::stream)
                    .collect(toUnmodifiableList());
        } catch (IOException exception) {
            if (exception instanceof SocketTimeoutException || exception.getCause() instanceof SocketTimeoutException) {
                LOGGER.debug(String.format("The client didn't get a respond within the configured time-out of [%d] milliseconds from: [%s]", timeout.toMillis(), url));
                return Collections.emptyList();
            }
            throw new GenericIOException(String.format("Failed getting certificate from: [%s]", url), exception);
        } finally {
            certificatesCollector.clear();
            SSLSessionUtils.invalidateCaches(sslFactoryForCertificateCapturing);
        }
    }

    URLConnection createConnection(URL url) throws IOException {
        return proxy != null ? url.openConnection(proxy) : url.openConnection();
    }

    List<X509Certificate> getRootCaFromChainIfPossible(List<X509Certificate> certificates) {
        if (!certificates.isEmpty()) {
            X509Certificate certificate = certificates.get(certificates.size() - 1);
            String issuer = certificate.getIssuerX500Principal().getName();
            String subject = certificate.getSubjectX500Principal().getName();

            boolean isSelfSignedCertificate = issuer.equals(subject);
            if (!isSelfSignedCertificate) {
                return getRootCaIfPossible(certificate);
            }
        }
        return Collections.emptyList();
    }

    List<X509Certificate> getRootCaIfPossible(X509Certificate x509Certificate) {
        List<X509Certificate> rootCaFromAuthorityInfoAccessExtension = getRootCaFromAuthorityInfoAccessExtensionIfPresent(x509Certificate);
        if (!rootCaFromAuthorityInfoAccessExtension.isEmpty()) {
            return rootCaFromAuthorityInfoAccessExtension;
        }

        List<X509Certificate> rootCaFromJdkTrustedCertificates = getRootCaFromJdkTrustedCertificates(x509Certificate);
        if (!rootCaFromJdkTrustedCertificates.isEmpty()) {
            return rootCaFromJdkTrustedCertificates;
        }

        return Collections.emptyList();
    }

    List<X509Certificate> getRootCaFromAuthorityInfoAccessExtensionIfPresent(X509Certificate certificate) {
        String certificateContent = certificate.toString();
        Matcher caIssuersMatcher = CA_ISSUERS_AUTHORITY_INFO_ACCESS.matcher(certificateContent);
        if (caIssuersMatcher.find()) {
            String issuerLocation = caIssuersMatcher.group(1);
            return getCertificatesFromRemoteFile(issuerLocation, certificate);
        }

        return Collections.emptyList();
    }

    List<X509Certificate> getCertificatesFromRemoteFile(String issuerLocation, X509Certificate intermediateCertificate) {
        try {
            URL url = URI.create(issuerLocation).toURL();
            URLConnection connection = createConnection(url);
            connection.setConnectTimeout((int) timeout.toMillis());
            connection.setReadTimeout((int) timeout.toMillis());
            if (connection instanceof HttpsURLConnection) {
                ((HttpsURLConnection) connection).setSSLSocketFactory(unsafeSslSocketFactory);
            }

            try(InputStream inputStream = connection.getInputStream()) {
                return CertificateUtils.parseDerCertificate(inputStream).stream()
                        .filter(X509Certificate.class::isInstance)
                        .map(X509Certificate.class::cast)
                        .filter(issuer -> isIssuerOfIntermediateCertificate(intermediateCertificate, issuer))
                        .collect(toUnmodifiableList());
            }
        } catch (Exception e) {
            LOGGER.debug(String.format("Skipped getting certificate from remote file while using the following location [%s]", issuerLocation), e);
            return Collections.emptyList();
        } finally {
            SSLSessionUtils.invalidateCaches(unsafeSslFactory);
        }
    }

    List<X509Certificate> getRootCaFromJdkTrustedCertificates(X509Certificate intermediateCertificate) {
        List<X509Certificate> jdkTrustedCertificates = CertificateUtils.getJdkTrustedCertificates();

        return jdkTrustedCertificates.stream()
                .filter(issuer -> isIssuerOfIntermediateCertificate(intermediateCertificate, issuer))
                .collect(toUnmodifiableList());
    }

    boolean isIssuerOfIntermediateCertificate(X509Certificate intermediateCertificate, X509Certificate issuer) {
        try {
            intermediateCertificate.verify(issuer.getPublicKey());
            return true;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            return false;
        }
    }

    List<X509Certificate> getCertificatesCollector() {
        return certificatesCollector;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private Proxy proxy = null;
        private PasswordAuthentication passwordAuthentication = null;
        private boolean shouldResolveRootCa = true;
        private Duration timeout = DEFAULT_TIMEOUT;
        private ClientRunnable clientRunnable = null;

        public Builder withProxy(Proxy proxy) {
            this.proxy = proxy;
            return this;
        }

        public Builder withPasswordAuthentication(PasswordAuthentication passwordAuthentication) {
            this.passwordAuthentication = passwordAuthentication;
            return this;
        }

        public Builder withResolvedRootCa(boolean shouldResolveRootCa) {
            this.shouldResolveRootCa = shouldResolveRootCa;
            return this;
        }

        public Builder withTimeout(int timeoutInMilliseconds) {
            return withTimeout(Duration.ofMillis(timeoutInMilliseconds));
        }

        public Builder withTimeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        public Builder withClientRunnable(ClientRunnable clientRunnable) {
            this.clientRunnable = clientRunnable;
            return this;
        }

        public CertificateExtractingClient build() {
            return new CertificateExtractingClient(shouldResolveRootCa, proxy, passwordAuthentication, timeout, clientRunnable);
        }

    }

}
