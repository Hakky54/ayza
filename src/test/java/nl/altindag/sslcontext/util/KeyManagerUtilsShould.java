package nl.altindag.sslcontext.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509KeyManager;

import org.junit.Test;

import nl.altindag.sslcontext.exception.GenericSecurityException;
import nl.altindag.sslcontext.keymanager.CompositeX509KeyManager;

public class KeyManagerUtilsShould {

    private static final String IDENTITY_FILE_NAME = "identity.jks";
    private static final String IDENTITY_TWO_FILE_NAME = "identity-two.jks";
    private static final char[] IDENTITY_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystores-for-unit-tests/";

    @Test
    public void createKeyManagerWithKeyStoreAndCustomAlgorithm() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identity = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        X509KeyManager keyManager = KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD, KeyManagerFactory.getDefaultAlgorithm());

        assertThat(keyManager).isNotNull();
    }

    @Test
    public void throwExceptionWhenCreatingKeyManagerWithInvalidAlgorithm() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identity = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);

        assertThatThrownBy(() -> KeyManagerUtils.createKeyManager(identity, IDENTITY_PASSWORD, "NONE"))
                .isInstanceOf(GenericSecurityException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: NONE KeyManagerFactory not available");

    }

    @Test
    public void combineMultipleKeyManagersIntoOne() throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {
        KeyStore identityOne = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_FILE_NAME, IDENTITY_PASSWORD);
        KeyStore identityTwo = KeystoreUtils.loadKeyStore(KEYSTORE_LOCATION + IDENTITY_TWO_FILE_NAME, IDENTITY_PASSWORD);

        X509KeyManager keyManagerOne = KeyManagerUtils.createKeyManager(identityOne, IDENTITY_PASSWORD);
        X509KeyManager keyManagerTwo = KeyManagerUtils.createKeyManager(identityTwo, IDENTITY_PASSWORD);

        X509KeyManager combinedKeyManager = KeyManagerUtils.combine(keyManagerOne, keyManagerTwo);

        assertThat(combinedKeyManager).isInstanceOf(CompositeX509KeyManager.class);
    }

}
