package nl.altindag.sslcontext.trustmanager;

import ch.qos.logback.classic.Level;
import nl.altindag.log.LogCaptor;
import nl.altindag.sslcontext.util.KeyStoreUtils;
import org.junit.Test;

import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

public class UnsafeTrustManagerShould {

    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";
    private static final char[] TRUSTSTORE_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_FILE_NAME = "identity.jks";
    private static final char[] KEYSTORE_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";

    @Test
    public void checkClientTrusted() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        LogCaptor<UnsafeTrustManager> logCaptor = LogCaptor.forClass(UnsafeTrustManager.class);

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509TrustManager trustManager = UnsafeTrustManager.INSTANCE;
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(0);
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> trustManager.checkClientTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getLogs(Level.DEBUG)).hasSize(1);
        assertThat(logCaptor.getLogs(Level.DEBUG)).contains("Accepting a client certificate: [CN=*.google.com, O=Google LLC, L=Mountain View, ST=California, C=US]");
    }

    @Test
    public void checkServerTrusted() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        LogCaptor<UnsafeTrustManager> logCaptor = LogCaptor.forClass(UnsafeTrustManager.class);

        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        X509TrustManager trustManager = UnsafeTrustManager.INSTANCE;

        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(0);

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getLogs(Level.DEBUG)).hasSize(1);
        assertThat(logCaptor.getLogs(Level.DEBUG)).contains("Accepting a server certificate: [CN=Prof Oak, OU=Oak Pokémon Research Lab, O=Oak Pokémon Research Lab, C=Pallet Town]");
    }

    @Test
    public void checkClientTrustedDoesNotLogAnythingWhenDebugLevelIsDisabled() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        LogCaptor<UnsafeTrustManager> logCaptor = LogCaptor.forClass(UnsafeTrustManager.class);
        logCaptor.setLogLevel(Level.INFO);

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509TrustManager trustManager = UnsafeTrustManager.INSTANCE;
        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(trustStore);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSize(0);
        assertThat(trustedCerts).hasSize(1);

        assertThatCode(() -> trustManager.checkClientTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getLogs(Level.DEBUG)).isEmpty();
        logCaptor.resetLogLevel();
    }

    @Test
    public void checkServerTrustedDoesNotLogAnythingWhenDebugLevelIsDisabled() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        LogCaptor<UnsafeTrustManager> logCaptor = LogCaptor.forClass(UnsafeTrustManager.class);
        logCaptor.setLogLevel(Level.INFO);

        X509Certificate[] trustedCerts = KeyStoreTestUtils.getTrustedX509Certificates(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + KEYSTORE_FILE_NAME, KEYSTORE_PASSWORD));

        X509TrustManager trustManager = UnsafeTrustManager.INSTANCE;

        assertThat(trustedCerts).hasSize(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(0);

        assertThatCode(() -> trustManager.checkServerTrusted(trustedCerts, "RSA"))
                .doesNotThrowAnyException();

        assertThat(logCaptor.getLogs(Level.DEBUG)).isEmpty();
        logCaptor.resetLogLevel();
    }

}
