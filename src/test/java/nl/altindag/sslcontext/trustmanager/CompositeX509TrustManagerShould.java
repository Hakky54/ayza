package nl.altindag.sslcontext.trustmanager;

import ch.qos.logback.classic.Level;
import nl.altindag.log.LogCaptor;
import nl.altindag.sslcontext.util.KeyStoreUtils;
import nl.altindag.sslcontext.util.TrustManagerUtils;
import org.junit.Test;
import sun.security.validator.ValidatorException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.*;

public class CompositeX509TrustManagerShould {

    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";
    private static final char[] TRUSTSTORE_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_FILE_NAME = "identity.jks";
    private static final char[] KEYSTORE_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";

    @Test
    public void createCompositeX509TrustManagerFromKeyStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        CompositeX509TrustManager trustManager = CompositeX509TrustManager.builder()
                                                                          .withTrustStores(trustStoreOne)
                                                                          .withTrustStores(trustStoreTwo)
                                                                          .build();

        assertThat(trustManager).isNotNull();

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
        assertThat(trustManager.getTrustManagers()).hasSize(2);
    }

    @Test
    public void createCompositeX509TrustManagerWithKeyStoreAndTrustManagerAlgorithm() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        CompositeX509TrustManager trustManager = CompositeX509TrustManager.builder()
                                                                          .withTrustStore(trustStore, KeyManagerFactory.getDefaultAlgorithm())
                                                                          .build();

        assertThat(trustManager.getTrustManagers()).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    public void createCompositeX509TrustManagerWithKeyStore() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        CompositeX509TrustManager trustManager = CompositeX509TrustManager.builder()
                                                                          .withTrustStore(trustStore)
                                                                          .build();

        assertThat(trustManager.getTrustManagers()).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    public void createCompositeX509TrustManagerFromKeyStoreWithBuilderPattern() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        CompositeX509TrustManager trustManager = CompositeX509TrustManager.builder()
                                                                          .withTrustStores(trustStoreOne, trustStoreTwo)
                                                                          .build();

        assertThat(trustManager).isNotNull();

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
        assertThat(trustManager.getTrustManagers()).hasSize(2);
    }

    @Test
    public void createCompositeX509TrustManagerFromListOfTrustManagersWithBuilderPattern() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        CompositeX509TrustManager trustManager = CompositeX509TrustManager.builder()
                                                                          .withTrustManagers(
                                                                                  Arrays.asList(TrustManagerUtils.createTrustManager(trustStoreOne),
                                                                                                TrustManagerUtils.createTrustManager(trustStoreTwo)))
                                                                          .build();

        assertThat(trustManager).isNotNull();

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
        assertThat(trustManager.getTrustManagers()).hasSize(2);
    }

    @Test
    public void checkClientTrusted() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509TrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        LogCaptor<CompositeX509TrustManager> logCaptor = LogCaptor.forClass(CompositeX509TrustManager.class);
        logCaptor.setLogLevel(Level.INFO);

        CompositeX509TrustManager compositeX509TrustManager = new CompositeX509TrustManager(Collections.singletonList(trustManager));
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> compositeX509TrustManager.checkClientTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getLogs()).isEmpty();
        logCaptor.resetLogLevel();
    }

    @Test
    public void checkClientTrustedLogsCertificateChainIfDebugIsEnabled() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509TrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        LogCaptor<CompositeX509TrustManager> logCaptor = LogCaptor.forClass(CompositeX509TrustManager.class);

        CompositeX509TrustManager compositeX509TrustManager = new CompositeX509TrustManager(Collections.singletonList(trustManager));
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> compositeX509TrustManager.checkClientTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getLogs(Level.DEBUG)).hasSize(1);
        assertThat(logCaptor.getLogs(Level.DEBUG).get(0))
                .contains("Received the following client certificate: [CN=*.google.com, O=Google LLC, L=Mountain View, ST=California, C=US]");
    }

    @Test
    public void checkServerTrusted() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-dummy-client.jks", TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        LogCaptor<CompositeX509TrustManager> logCaptor = LogCaptor.forClass(CompositeX509TrustManager.class);
        logCaptor.setLogLevel(Level.INFO);

        CompositeX509TrustManager trustManager = CompositeX509TrustManager.builder()
                                                                          .withTrustStores(trustStore)
                                                                          .build();
        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getLogs()).isEmpty();
        logCaptor.resetLogLevel();
    }

    @Test
    public void checkServerTrustedLogsCertificateChainIfDebugIsEnabled() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-dummy-client.jks", TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        LogCaptor<CompositeX509TrustManager> logCaptor = LogCaptor.forClass(CompositeX509TrustManager.class);

        CompositeX509TrustManager trustManager = CompositeX509TrustManager.builder()
                .withTrustStores(trustStore)
                .build();
        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getLogs(Level.DEBUG)).hasSize(1);
        assertThat(logCaptor.getLogs(Level.DEBUG).get(0))
                .contains("Received the following server certificate: [CN=Prof Oak, OU=Oak Pokémon Research Lab, O=Oak Pokémon Research Lab, C=Pallet Town]");
    }

    @Test
    public void throwsExceptionWhenCheckServerTrustedDoesNotTrustTheSuppliedCertificate() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        CompositeX509TrustManager trustManager = CompositeX509TrustManager.builder()
                                                                          .withTrustManagers(TrustManagerUtils.createTrustManager(trustStore))
                                                                          .build();
        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        assertThatThrownBy(() -> trustManager.checkServerTrusted(trustedCerts, "RSA"))
                .isInstanceOf(CertificateException.class)
                .hasMessage("None of the TrustManagers trust this certificate chain")
                .hasSuppressedException(new ValidatorException("PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target"));
    }

    @Test
    public void combineTrustManagersWhileFilteringDuplicateCertificates() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509TrustManager trustManager = new CompositeX509TrustManager(Arrays.asList(
                TrustManagerUtils.createTrustManager(trustStore), TrustManagerUtils.createTrustManager(trustStore)));

        assertThat(trustStore.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
    }

    @Test
    public void throwsExceptionWhenCheckClientTrustedDoesNotTrustTheSuppliedCertificate() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509TrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD));

        CompositeX509TrustManager compositeX509TrustManager = new CompositeX509TrustManager(Collections.singletonList(trustManager));
        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);
        assertThat(trustedCerts).hasSize(1);

        assertThatThrownBy(() -> compositeX509TrustManager.checkClientTrusted(trustedCerts, "RSA"))
                .isInstanceOf(CertificateException.class)
                .hasMessage("None of the TrustManagers trust this certificate chain")
                .hasSuppressedException(new ValidatorException("PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target"));
    }

}
