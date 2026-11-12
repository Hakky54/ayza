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

import nl.altindag.desidero.WindowsCertificateUtils;
import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.exception.GenericSecurityException;
import nl.altindag.ssl.exception.GenericTrustManagerException;
import nl.altindag.ssl.trustmanager.AggregatedX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.DummyX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.EnhanceableX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.HotSwappableX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.InflatableX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.JdkX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.LoggingX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.SystemX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.UnsafeX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.X509TrustManagerWrapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertificateException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class TrustManagerUtilsShould {

    private static final String TRUSTSTORE_FILE_NAME = "truststore.jks";
    private static final char[] TRUSTSTORE_PASSWORD = new char[] {'s', 'e', 'c', 'r', 'e', 't'};
    private static final String KEYSTORE_LOCATION = "keystore/";
    private static final String ORIGINAL_OS_NAME = System.getProperty("os.name");

    @Test
    void combineTrustManagers() throws KeyStoreException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils
                .combine(TrustManagerUtils.createTrustManager(trustStoreOne), TrustManagerUtils.createTrustManager(trustStoreTwo));

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void unwrapCombinedTrustManagersAndRecombineIntoSingleBaseTrustManager() throws KeyStoreException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManagerOne = TrustManagerUtils.createTrustManager(trustStoreOne);
        X509ExtendedTrustManager trustManagerTwo = TrustManagerUtils.createTrustManager(trustStoreTwo);

        X509ExtendedTrustManager combinedTrustManager = TrustManagerUtils.combine(trustManagerOne, trustManagerTwo);
        X509ExtendedTrustManager combinedCombinedTrustManager = TrustManagerUtils.combine(combinedTrustManager, trustManagerOne, trustManagerTwo);

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(combinedTrustManager.getAcceptedIssuers()).hasSize(2);
        assertThat(combinedCombinedTrustManager.getAcceptedIssuers()).hasSize(4);

        assertThat(combinedTrustManager).isInstanceOf(AggregatedX509ExtendedTrustManager.class);
        assertThat(combinedCombinedTrustManager).isInstanceOf(AggregatedX509ExtendedTrustManager.class);
        assertThat(((AggregatedX509ExtendedTrustManager) combinedTrustManager).getInnerTrustManagers().size()).isEqualTo(2);
        assertThat(((AggregatedX509ExtendedTrustManager) combinedCombinedTrustManager).getInnerTrustManagers().size()).isEqualTo(4);
    }

    @Test
    void combineTrustManagersWithKeyStores() throws KeyStoreException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils
                .combine(TrustManagerUtils.createTrustManager(trustStoreOne, trustStoreTwo));

        assertThat(trustStoreOne.size()).isEqualTo(1);
        assertThat(trustStoreTwo.size()).isEqualTo(1);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(2);
    }

    @Test
    void wrapIfNeeded() {
        X509TrustManager trustManager = mock(X509TrustManager.class);
        X509ExtendedTrustManager extendedTrustManager = TrustManagerUtils.wrapIfNeeded(trustManager);

        assertThat(extendedTrustManager).isInstanceOf(X509TrustManagerWrapper.class);
    }

    @Test
    void doNotWrapWhenInstanceIsX509ExtendedTrustManager() {
        X509ExtendedTrustManager trustManager = mock(X509ExtendedTrustManager.class);
        X509ExtendedTrustManager extendedTrustManager = TrustManagerUtils.wrapIfNeeded(trustManager);

        assertThat(extendedTrustManager)
                .isEqualTo(trustManager)
                .isNotInstanceOf(X509TrustManagerWrapper.class);
    }

    @Test
    void createTrustManagerWithCustomSecurityProviderBasedOnTheName() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore, TrustManagerFactory.getDefaultAlgorithm(), "SunJSSE");

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerWithCustomSecurityProvider() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        Provider sunJSSE = Security.getProvider("SunJSSE");

        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore, TrustManagerFactory.getDefaultAlgorithm(), sunJSSE);

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerWithJdkTrustedCertificatesWhenProvidingNullAsTrustStore() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager((KeyStore) null);

        assertThat(trustManager).isNotNull();
        assertThat(trustManager.getAcceptedIssuers()).hasSizeGreaterThan(10);
    }

    @Test
    void createTrustManagerWithJdkTrustedCertificatesWhenCallingCreateTrustManagerWithJdkTrustedCertificates() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates();

        assertThat(trustManager).isNotNull().isInstanceOf(JdkX509ExtendedTrustManager.class);
        assertThat((trustManager).getAcceptedIssuers()).hasSizeGreaterThan(10);
    }

    @Test
    void createTrustManagerWithCertificates() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(
                Arrays.asList(TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates().getAcceptedIssuers())
        );

        assertThat(trustManager).isNotNull();
        assertThat((trustManager).getAcceptedIssuers()).hasSizeGreaterThan(10);
    }

    @Test
    void createTrustManagerWithSystemTrustedCertificate() {
        String operatingSystem = System.getProperty("os.name").toLowerCase();

        try (MockedStatic<KeyStoreUtils> keyStoreUtilsMockedStatic = mockStatic(KeyStoreUtils.class, invocation -> {
            Method method = invocation.getMethod();
            if ("createKeyStore".equals(method.getName())
                    && method.getParameterCount() == 2
                    && operatingSystem.contains("mac")) {
                return KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
            } else if ("createTrustStore".equals(method.getName())
                    && method.getParameterCount() == 1
                    && method.getParameters()[0].getType().equals(List.class)
                    && operatingSystem.contains("mac")) {
                return KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-without-password.jks", null);
            } else {
                return invocation.callRealMethod();
            }
        })) {
            Optional<X509ExtendedTrustManager> trustManager = TrustManagerUtils.createTrustManagerWithSystemTrustedCertificates();
            if (operatingSystem.contains("mac") || operatingSystem.contains("windows") || operatingSystem.contains("linux")) {
                assertThat(trustManager).isPresent();
                assertThat(trustManager.get()).isInstanceOf(SystemX509ExtendedTrustManager.class);
                assertThat((trustManager).get().getAcceptedIssuers()).hasSizeGreaterThan(0);
            }
        }
    }

    @Test
    void createSystemTrustManagerWithWindowsIntermediateCertificates() {
        KeyStore rootStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore myStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509Certificate root = TrustManagerUtils.createTrustManager(rootStore).getAcceptedIssuers()[0];
        X509Certificate my = TrustManagerUtils.createTrustManager(myStore).getAcceptedIssuers()[0];

        X509Certificate intermediate = mock(X509Certificate.class);
        WindowsCertificateUtils windows = mock(WindowsCertificateUtils.class);

        when(windows.getRootCertificates()).thenReturn(Collections.singletonList(root));
        when(windows.getMyCertificates()).thenReturn(Collections.singletonList(my));
        when(windows.getIntermediateCertificates()).thenReturn(Collections.singletonList(intermediate));

        String originalOsName = System.getProperty("os.name");

        try (MockedStatic<KeyStoreUtils> keyStores = mockStatic(KeyStoreUtils.class); MockedStatic<WindowsCertificateUtils> windowsUtils = mockStatic(WindowsCertificateUtils.class)) {

            System.setProperty("os.name", "Windows 11");

            keyStores.when(KeyStoreUtils::loadSystemKeyStores).thenReturn(Arrays.asList(rootStore, myStore));

            windowsUtils.when(WindowsCertificateUtils::getInstance).thenReturn(windows);

            Optional<X509ExtendedTrustManager> result = TrustManagerUtils.createTrustManagerWithSystemTrustedCertificates();

            assertThat(result).isPresent();
            assertThat(result.get()).isInstanceOf(SystemX509ExtendedTrustManager.class);

            assertThat(Arrays.asList(result.get().getAcceptedIssuers())).contains(root, my);

            verify(windows, times(1)).getIntermediateCertificates();
            verify(windows, times(1)).getRootCertificates();
            verify(windows, times(1)).getMyCertificates();

        } finally {
            System.setProperty("os.name", originalOsName);
        }
    }

    @Test
    void createSystemTrustManagerWithoutWindowsIntermediateCertificates() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate trustedCertificate = TrustManagerUtils.createTrustManager(trustStore).getAcceptedIssuers()[0];

        WindowsCertificateUtils windows = mock(WindowsCertificateUtils.class);
        when(windows.getIntermediateCertificates()).thenReturn(Collections.emptyList());

        String originalOsName = System.getProperty("os.name");

        try (MockedStatic<KeyStoreUtils> keyStores = mockStatic(KeyStoreUtils.class); MockedStatic<WindowsCertificateUtils> windowsUtils = mockStatic(WindowsCertificateUtils.class)) {
            System.setProperty("os.name", "Windows 11");

            keyStores.when(KeyStoreUtils::loadSystemKeyStores).thenReturn(Collections.singletonList(trustStore));
            windowsUtils.when(WindowsCertificateUtils::getInstance).thenReturn(windows);

            Optional<X509ExtendedTrustManager> result = TrustManagerUtils.createTrustManagerWithSystemTrustedCertificates();

            assertThat(result).isPresent();
            assertThat(result.get()).isInstanceOf(SystemX509ExtendedTrustManager.class);
            assertThat(result.get().getAcceptedIssuers()).contains(trustedCertificate);

            verify(windows, times(1)).getIntermediateCertificates();
            verify(windows, never()).getRootCertificates();
            verify(windows, never()).getMyCertificates();

        } finally {
            System.setProperty("os.name", originalOsName);
        }
    }

    @Test
    void createSystemTrustManagerOnLinuxWithoutCallingWindowsCertificateUtils() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509Certificate trustedCertificate = TrustManagerUtils.createTrustManager(trustStore).getAcceptedIssuers()[0];

        String originalOsName = System.getProperty("os.name");
        WindowsCertificateUtils windows = mock(WindowsCertificateUtils.class);

        try (MockedStatic<KeyStoreUtils> keyStores = mockStatic(KeyStoreUtils.class); MockedStatic<WindowsCertificateUtils> windowsUtils = mockStatic(WindowsCertificateUtils.class)) {
            System.setProperty("os.name", "Linux");
            windowsUtils.when(WindowsCertificateUtils::getInstance).thenReturn(windows);

            keyStores.when(KeyStoreUtils::loadSystemKeyStores).thenReturn(Collections.singletonList(trustStore));

            Optional<X509ExtendedTrustManager> result = TrustManagerUtils.createTrustManagerWithSystemTrustedCertificates();

            assertThat(result).isPresent();
            assertThat(result.get()).isInstanceOf(SystemX509ExtendedTrustManager.class);
            assertThat(result.get().getAcceptedIssuers()).contains(trustedCertificate);

            verify(windows, never()).getRootCertificates();
            verify(windows, never()).getMyCertificates();
            verify(windows, never()).getIntermediateCertificates();
            verify(windows, never()).getTrustStores();
        } finally {
            System.setProperty("os.name", originalOsName);
        }
    }

    @Test
    void createTrustManagerWhenProvidingACustomTrustStore() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);

        assertThat(trustManager).isNotNull();
        assertThat((trustManager).getAcceptedIssuers()).hasSize(1);
    }

    @Test
    void createUnsafeTrustManager() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createUnsafeTrustManager();

        assertThat(trustManager)
                .isNotNull()
                .isInstanceOf(UnsafeX509ExtendedTrustManager.class)
                .isEqualTo(TrustManagerUtils.createUnsafeTrustManager());
    }

    @Test
    void createLoggingTrustManager() {
        X509ExtendedTrustManager unsafeTrustManager = TrustManagerUtils.createUnsafeTrustManager();
        X509ExtendedTrustManager trustManager = TrustManagerUtils.createLoggingTrustManager(unsafeTrustManager);

        assertThat(trustManager).isInstanceOf(LoggingX509ExtendedTrustManager.class);

        X509ExtendedTrustManager innerTrustManager = ((LoggingX509ExtendedTrustManager) trustManager).getInnerTrustManager();
        assertThat(innerTrustManager).isInstanceOf(UnsafeX509ExtendedTrustManager.class);
    }

    @Test
    void createLoggingTrustManagerFromBuilder() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustManager(TrustManagerUtils.createUnsafeTrustManager())
                .withLoggingTrustManager(true)
                .build();

        assertThat(trustManager).isInstanceOf(LoggingX509ExtendedTrustManager.class);

        X509ExtendedTrustManager innerTrustManager = ((LoggingX509ExtendedTrustManager) trustManager).getInnerTrustManager();
        assertThat(innerTrustManager).isInstanceOf(UnsafeX509ExtendedTrustManager.class);
    }

    @Test
    void trustManagerShouldSwapEvenThoughItContainsALoggingTrustManager() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustManager(TrustManagerUtils.createUnsafeTrustManager())
                .withSwappableTrustManager(true)
                .withLoggingTrustManager(true)
                .build();

        assertThat(trustManager).isInstanceOf(HotSwappableX509ExtendedTrustManager.class);
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();

        X509ExtendedTrustManager innerTrustManager = ((HotSwappableX509ExtendedTrustManager) trustManager).getInnerTrustManager();
        assertThat(innerTrustManager).isInstanceOf(LoggingX509ExtendedTrustManager.class);

        X509ExtendedTrustManager innerInnerTrustManager = ((LoggingX509ExtendedTrustManager) innerTrustManager).getInnerTrustManager();
        assertThat(innerInnerTrustManager).isInstanceOf(UnsafeX509ExtendedTrustManager.class);

        X509ExtendedTrustManager trustManagerWithJdkTrustedCertificates = TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates();
        TrustManagerUtils.swapTrustManager(trustManager, trustManagerWithJdkTrustedCertificates);
        assertThat(trustManager.getAcceptedIssuers()).isNotEmpty();
    }

    @Test
    void trustManagerShouldSwapEvenThoughTheNewTrustManagerIsInflatableTrustManager() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustStores(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD))
                .withSwappableTrustManager(true)
                .build();

        assertThat(trustManager).isInstanceOf(HotSwappableX509ExtendedTrustManager.class);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        X509ExtendedTrustManager newTrustManager = TrustManagerUtils.createInflatableTrustManager();

        TrustManagerUtils.swapTrustManager(trustManager, newTrustManager);
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();
    }

    @Test
    void trustManagerShouldNotSwapWhenLoggingTrustManagerDoesNotContainSwappableTrustManager() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustManager(TrustManagerUtils.createUnsafeTrustManager())
                .withSwappableTrustManager(false)
                .withLoggingTrustManager(true)
                .build();

        assertThat(trustManager).isInstanceOf(LoggingX509ExtendedTrustManager.class);
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();

        X509ExtendedTrustManager innerTrustManager = ((LoggingX509ExtendedTrustManager) trustManager).getInnerTrustManager();
        assertThat(innerTrustManager).isInstanceOf(UnsafeX509ExtendedTrustManager.class);

        X509ExtendedTrustManager trustManagerWithJdkTrustedCertificates = TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates();
        assertThatThrownBy(() -> TrustManagerUtils.swapTrustManager(trustManager, trustManagerWithJdkTrustedCertificates))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("The baseTrustManager is from the instance of [nl.altindag.ssl.trustmanager.LoggingX509ExtendedTrustManager] " +
                        "and should be an instance of [nl.altindag.ssl.trustmanager.HotSwappableX509ExtendedTrustManager].");
    }

    @Test
    void createEnhanceableTrustManagerDoesSkipCallingBaseTrustManagerWhenCustomValidatorReturnsTrue() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        X509ExtendedTrustManager enhanceableTrustManager = TrustManagerUtils.createEnhanceableTrustManager(baseTrustManager, trustManagerParameters -> "RSA".equals(trustManagerParameters.getAuthType()));

        enhanceableTrustManager.checkServerTrusted(null, "RSA");
        verify(baseTrustManager, times(0)).checkServerTrusted(null, "RSA");
    }

    @Test
    void createEnhanceableTrustManagerDoesCallsBaseTrustManagerWhenCustomValidatorReturnsFalse() throws CertificateException {
        X509ExtendedTrustManager baseTrustManager = mock(X509ExtendedTrustManager.class);
        X509ExtendedTrustManager enhanceableTrustManager = TrustManagerUtils.createEnhanceableTrustManager(baseTrustManager, trustManagerParameters -> "RSA".equals(trustManagerParameters.getAuthType()));

        enhanceableTrustManager.checkServerTrusted(null, "ASR");
        verify(baseTrustManager, times(1)).checkServerTrusted(null, "ASR");
    }

    @Test
    void trustManagerShouldSwapEvenThoughItContainsAnEnhanceableTrustManager() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustManagers(TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates())
                .withSwappableTrustManager(true)
                .withTrustEnhancer(true)
                .build();

        assertThat(trustManager).isInstanceOf(HotSwappableX509ExtendedTrustManager.class);
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();

        X509ExtendedTrustManager innerTrustManager = ((HotSwappableX509ExtendedTrustManager) trustManager).getInnerTrustManager();
        assertThat(innerTrustManager).isInstanceOf(EnhanceableX509ExtendedTrustManager.class);
        assertThat(innerTrustManager.getAcceptedIssuers()).isEmpty();

        X509ExtendedTrustManager innerInnerTrustManager = ((EnhanceableX509ExtendedTrustManager) innerTrustManager).getInnerTrustManager();
        assertThat(innerInnerTrustManager.getAcceptedIssuers()).isNotEmpty();

        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager newTrustManager = TrustManagerUtils.createTrustManager(trustStoreOne);

        TrustManagerUtils.swapTrustManager(trustManager, newTrustManager);
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();

        innerTrustManager = ((HotSwappableX509ExtendedTrustManager) trustManager).getInnerTrustManager();
        assertThat(innerTrustManager).isInstanceOf(EnhanceableX509ExtendedTrustManager.class);
        assertThat(innerTrustManager.getAcceptedIssuers()).isEmpty();

        assertThat(((EnhanceableX509ExtendedTrustManager) innerTrustManager).getInnerTrustManager().getAcceptedIssuers()).isNotEmpty();
        assertThat(((EnhanceableX509ExtendedTrustManager) innerTrustManager).getInnerTrustManager())
                .isNotEqualTo(innerInnerTrustManager)
                .isEqualTo(newTrustManager);
    }

    @Test
    void trustManagerShouldSwapEvenThoughItContainsAnEnhanceableTrustManagerWrappedInALoggingTrustManager() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustManagers(TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates())
                .withSwappableTrustManager(true)
                .withTrustEnhancer(true)
                .withLoggingTrustManager(true)
                .build();

        assertThat(trustManager).isInstanceOf(HotSwappableX509ExtendedTrustManager.class);
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();

        X509ExtendedTrustManager innerTrustManager = ((HotSwappableX509ExtendedTrustManager) trustManager).getInnerTrustManager();
        assertThat(innerTrustManager).isInstanceOf(LoggingX509ExtendedTrustManager.class);

        X509ExtendedTrustManager innerInnerTrustManager = ((LoggingX509ExtendedTrustManager) innerTrustManager).getInnerTrustManager();
        assertThat(innerInnerTrustManager).isInstanceOf(EnhanceableX509ExtendedTrustManager.class);
        assertThat(innerInnerTrustManager.getAcceptedIssuers()).isEmpty();

        X509ExtendedTrustManager innerInnerInnerTrustManager = ((EnhanceableX509ExtendedTrustManager) innerInnerTrustManager).getInnerTrustManager();
        assertThat(innerInnerInnerTrustManager.getAcceptedIssuers()).isNotEmpty();

        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        X509ExtendedTrustManager newTrustManager = TrustManagerUtils.createTrustManager(trustStoreOne);

        TrustManagerUtils.swapTrustManager(trustManager, newTrustManager);
        assertThat(trustManager.getAcceptedIssuers()).isEmpty();

        innerTrustManager = ((HotSwappableX509ExtendedTrustManager) trustManager).getInnerTrustManager();
        assertThat(innerTrustManager).isInstanceOf(LoggingX509ExtendedTrustManager.class);
        assertThat(innerTrustManager.getAcceptedIssuers()).isEmpty();

        innerInnerTrustManager = ((LoggingX509ExtendedTrustManager) innerTrustManager).getInnerTrustManager();
        assertThat(innerInnerTrustManager).isInstanceOf(EnhanceableX509ExtendedTrustManager.class);
        assertThat(innerInnerTrustManager.getAcceptedIssuers()).isEmpty();

        assertThat(((EnhanceableX509ExtendedTrustManager) innerInnerTrustManager).getInnerTrustManager().getAcceptedIssuers()).isNotEmpty();
        assertThat(((EnhanceableX509ExtendedTrustManager) innerInnerTrustManager).getInnerTrustManager())
                .isNotEqualTo(innerInnerTrustManager)
                .isEqualTo(newTrustManager);
    }

    @Test
    void createTrustManagerFromMultipleTrustManagers() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManagerOne = TrustManagerUtils.createTrustManager(trustStoreOne);
        X509ExtendedTrustManager trustManagerTwo = TrustManagerUtils.createTrustManager(trustStoreTwo);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustManager(trustManagerOne)
                .withTrustManager(trustManagerTwo)
                .build();

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromMultipleTrustManagersUsingVarArgs() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManagerOne = TrustManagerUtils.createTrustManager(trustStoreOne);
        X509ExtendedTrustManager trustManagerTwo = TrustManagerUtils.createTrustManager(trustStoreTwo);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustManagers(trustManagerOne, trustManagerTwo)
                .build();

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromMultipleTrustManagersUsingList() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManagerOne = TrustManagerUtils.createTrustManager(trustStoreOne);
        X509ExtendedTrustManager trustManagerTwo = TrustManagerUtils.createTrustManager(trustStoreTwo);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustManagers(Arrays.asList(trustManagerOne, trustManagerTwo))
                .build();

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromMultipleTrustStoresUsingVarArgs() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustStores(trustStoreOne, trustStoreTwo)
                .build();

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromMultipleTrustStoresUsingList() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustStores(Arrays.asList(trustStoreOne, trustStoreTwo))
                .build();

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromMultipleTrustStores() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustStore(trustStoreOne)
                .withTrustStore(trustStoreTwo)
                .build();

        assertThat(trustManager).isNotNull();
    }

    @Test
    void loadLinuxSystemKeyStoreReturnsOptionalOfEmptyIfThereAreNoKeyStoresPresent() {
        System.setProperty("os.name", "linux");

        try (MockedStatic<KeyStoreUtils> keyStoreUtilsMock = mockStatic(KeyStoreUtils.class, invocation -> {
                 Method method = invocation.getMethod();
                 if ("loadSystemKeyStores".equals(method.getName()) && method.getParameterCount() == 0) {
                     return Collections.emptyList();
                 } else {
                     return invocation.callRealMethod();
                 }
             })) {
            Optional<X509ExtendedTrustManager> trustManager = TrustManagerUtils.createTrustManagerWithSystemTrustedCertificates();
            assertThat(trustManager).isNotPresent();
        } finally {
            resetOsName();
        }
    }

    @Test
    void createTrustManagerFromMultipleTrustStoresWithTrustManagerFactoryAlgorithm() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustStore(trustStoreOne, TrustManagerFactory.getDefaultAlgorithm())
                .withTrustStore(trustStoreTwo, TrustManagerFactory.getDefaultAlgorithm())
                .build();

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromManagerParameters() throws NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        CertPathTrustManagerParameters certPathTrustManagerParametersOne = createTrustManagerParameters(trustStoreOne);
        CertPathTrustManagerParameters certPathTrustManagerParametersTwo = createTrustManagerParameters(trustStoreTwo);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(certPathTrustManagerParametersOne, certPathTrustManagerParametersTwo);

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromManagerParametersWithTrustManagerFactoryAlgorithm() throws NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        CertPathTrustManagerParameters certPathTrustManagerParameters = createTrustManagerParameters(trustStore);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(certPathTrustManagerParameters, TrustManagerFactory.getDefaultAlgorithm());

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromManagerParametersWithSecurityProviderName() throws NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        CertPathTrustManagerParameters certPathTrustManagerParameters = createTrustManagerParameters(trustStore);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(certPathTrustManagerParameters, TrustManagerFactory.getDefaultAlgorithm(), "SunJSSE");

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createTrustManagerFromManagerParametersWithSecurityProvider() throws NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        CertPathTrustManagerParameters certPathTrustManagerParameters = createTrustManagerParameters(trustStore);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(certPathTrustManagerParameters, TrustManagerFactory.getDefaultAlgorithm(), Security.getProvider("SunJSSE"));

        assertThat(trustManager).isNotNull();
    }

    @Test
    void createOnlyUnsafeTrustManagerWhileProvidingMultipleTrustManagers() {
        LogCaptor logCaptor = LogCaptor.forRoot();

        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.combine(
                TrustManagerUtils.createTrustManager(trustStore),
                TrustManagerUtils.createUnsafeTrustManager()
        );

        assertThat(trustManager).isInstanceOf(UnsafeX509ExtendedTrustManager.class);

        assertThat(logCaptor.getDebugLogs()).contains("Unsafe TrustManager is being used therefore other trust managers will not be included for constructing the base trust manager");
    }

    @Test
    void doNotLogAnythingWhenUnsafeTrustManagerIsBeingUsedWithoutAdditionalTrustManagers() {
        LogCaptor logCaptor = LogCaptor.forRoot();

        X509ExtendedTrustManager trustManager = TrustManagerUtils.combine(
                TrustManagerUtils.createUnsafeTrustManager()
        );

        assertThat(trustManager).isInstanceOf(UnsafeX509ExtendedTrustManager.class);

        assertThat(logCaptor.getLogs()).isEmpty();
    }

    @Test
    void ignoreOtherTrustMaterialIfDummyTrustManagerIsPresent() {
        LogCaptor logCaptor = LogCaptor.forRoot();

        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustStore(trustStoreOne)
                .withTrustStore(trustStoreTwo)
                .withTrustManager(TrustManagerUtils.createDummyTrustManager())
                .build();

        assertThat(trustManager).isInstanceOf(DummyX509ExtendedTrustManager.class);
        assertThat(logCaptor.getDebugLogs()).contains("Dummy TrustManager is being used therefore other trust managers will not be included for constructing the base trust manager");
    }

    @Test
    void doNotLogAnythingWhenDummyTrustManagerIsBeingUsedWithoutAdditionalTrustManagers() {
        LogCaptor logCaptor = LogCaptor.forRoot();

        X509ExtendedTrustManager trustManager = TrustManagerUtils.combine(
                TrustManagerUtils.createDummyTrustManager()
        );

        assertThat(trustManager).isInstanceOf(DummyX509ExtendedTrustManager.class);

        assertThat(logCaptor.getLogs()).isEmpty();
    }

    @Test
    void addCertificatesToInflatableX509ExtendedTrustManager() {
        X509Certificate certificate = mock(X509Certificate.class);
        List<X509Certificate> certificates = Collections.singletonList(certificate);

        InflatableX509ExtendedTrustManager trustManager = mock(InflatableX509ExtendedTrustManager.class);
        TrustManagerUtils.addCertificate(trustManager, certificates);

        verify(trustManager, times(1)).addCertificates(certificates);
    }

    @Test
    void addCertificateToInflatableX509ExtendedTrustManager() {
        X509Certificate certificate = mock(X509Certificate.class);

        InflatableX509ExtendedTrustManager trustManager = mock(InflatableX509ExtendedTrustManager.class);
        TrustManagerUtils.addCertificate(trustManager, certificate);

        verify(trustManager, times(1)).addCertificates(Collections.singletonList(certificate));
    }

    @Test
    void addCertificateToInflatableX509ExtendedTrustManagerEvenThoughItIsWrappedInAHotSwappableX509ExtendedTrustManager() {
        X509Certificate certificate = mock(X509Certificate.class);
        List<X509Certificate> certificates = Collections.singletonList(certificate);

        InflatableX509ExtendedTrustManager inflatableX509ExtendedTrustManager = mock(InflatableX509ExtendedTrustManager.class);
        HotSwappableX509ExtendedTrustManager hotSwappableX509ExtendedTrustManager = mock(HotSwappableX509ExtendedTrustManager.class);
        when(hotSwappableX509ExtendedTrustManager.getInnerTrustManager()).thenReturn(inflatableX509ExtendedTrustManager);

        TrustManagerUtils.addCertificate(hotSwappableX509ExtendedTrustManager, certificates);

        verify(inflatableX509ExtendedTrustManager, times(1)).addCertificates(certificates);
    }

    @Test
    void addCertificateToInflatableX509ExtendedTrustManagerEvenThoughItIsWrappedInAHotSwappableX509ExtendedTrustManagerWhichIsWrappedIntoAAggregatedX509ExtendedTrustManager() {
        X509Certificate certificate = mock(X509Certificate.class);
        List<X509Certificate> certificates = Collections.singletonList(certificate);

        InflatableX509ExtendedTrustManager inflatableX509ExtendedTrustManager = mock(InflatableX509ExtendedTrustManager.class);
        X509ExtendedTrustManager jdkTrustManager = TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates();
        X509ExtendedTrustManager combinedTrustManager = TrustManagerUtils.combine(inflatableX509ExtendedTrustManager, jdkTrustManager);
        HotSwappableX509ExtendedTrustManager hotSwappableX509ExtendedTrustManager = (HotSwappableX509ExtendedTrustManager) TrustManagerUtils.createSwappableTrustManager(combinedTrustManager);

        TrustManagerUtils.addCertificate(hotSwappableX509ExtendedTrustManager, certificates);

        verify(inflatableX509ExtendedTrustManager, times(1)).addCertificates(certificates);
    }

    @Test
    void addCertificateToInflatableX509ExtendedTrustManagerEvenThoughItIsWrappedInAAggregatedX509ExtendedTrustManager() {
        X509Certificate certificate = mock(X509Certificate.class);
        List<X509Certificate> certificates = Collections.singletonList(certificate);

        InflatableX509ExtendedTrustManager inflatableX509ExtendedTrustManager = mock(InflatableX509ExtendedTrustManager.class);
        AggregatedX509ExtendedTrustManager aggregatedX509ExtendedTrustManager = mock(AggregatedX509ExtendedTrustManager.class);
        when(aggregatedX509ExtendedTrustManager.getInnerTrustManagers()).thenReturn(Collections.singletonList(inflatableX509ExtendedTrustManager));

        TrustManagerUtils.addCertificate(aggregatedX509ExtendedTrustManager, certificates);

        verify(inflatableX509ExtendedTrustManager, times(1)).addCertificates(certificates);
    }

    private CertPathTrustManagerParameters createTrustManagerParameters(KeyStore trustStore) throws NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException {
        CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
        PKIXRevocationChecker revocationChecker = (PKIXRevocationChecker) certPathBuilder.getRevocationChecker();
        revocationChecker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustStore, new X509CertSelector());
        pkixParams.addCertPathChecker(revocationChecker);
        return new CertPathTrustManagerParameters(pkixParams);
    }

    @Test
    void throwExceptionWhenInvalidTrustManagerAlgorithmIsProvided() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, "ABCD"))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: ABCD TrustManagerFactory not available");
    }

    @Test
    void throwExceptionWhenInvalidSecurityProviderNameIsProvided() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, trustManagerFactoryAlgorithm, "test"))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("java.security.NoSuchProviderException: no such provider: test");
    }

    @Test
    void throwExceptionWhenInvalidSecurityProviderNameIsProvidedForTheTrustManagerFactoryAlgorithm() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, trustManagerFactoryAlgorithm, "SUN"))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: no such algorithm: PKIX for provider SUN");
    }

    @Test
    void throwExceptionWhenInvalidSecurityProviderIsProvidedForTheTrustManagerFactoryAlgorithm() {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        Provider sunSecurityProvider = Security.getProvider("SUN");

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, trustManagerFactoryAlgorithm, sunSecurityProvider))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: no such algorithm: PKIX for provider SUN");
    }

    @Test
    void throwExceptionWhenInvalidTrustManagerAlgorithmIsProvidedWhenUsingManagerFactoryParameters() {
        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(mock(ManagerFactoryParameters.class), "ABCD"))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: ABCD TrustManagerFactory not available");
    }

    @Test
    void throwExceptionWhenInvalidSecurityProviderIsProvidedForTheTrustManagerFactoryAlgorithmWhenUsingManagerFactoryParameters() {
        String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        Provider sunSecurityProvider = Security.getProvider("SUN");

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(mock(ManagerFactoryParameters.class), trustManagerFactoryAlgorithm, sunSecurityProvider))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: no such algorithm: PKIX for provider SUN");
    }

    @Test
    void throwExceptionWhenInvalidSecurityProviderNameIsProvidedForTheTrustManagerFactoryAlgorithmWhenUsingManagerFactoryParameters() {
        String trustManagerFactoryAlgorithm = TrustManagerFactory.getDefaultAlgorithm();

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(mock(ManagerFactoryParameters.class), trustManagerFactoryAlgorithm, "SUN"))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("java.security.NoSuchAlgorithmException: no such algorithm: PKIX for provider SUN");
    }

    @Test
    void throwExceptionWhenSomethingUnexpectedHappensWhileInitializingTrustManagerWithManagerFactoryParameters() throws InvalidAlgorithmParameterException {
        TrustManagerFactory trustManagerFactory = mock(TrustManagerFactory.class);
        doThrow(new InvalidAlgorithmParameterException("KABOOM!!"))
                .when(trustManagerFactory).init(any(ManagerFactoryParameters.class));

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(mock(ManagerFactoryParameters.class), trustManagerFactory))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessageContaining("KABOOM!!");
    }

    @Test
    void throwGenericSecurityExceptionWhenTrustManagerFactoryCanNotInitializeWithTheProvidedTrustStore() throws KeyStoreException {
        KeyStore trustStore = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        TrustManagerFactory trustManagerFactory = mock(TrustManagerFactory.class);

        doThrow(new KeyStoreException("KABOOOM!")).when(trustManagerFactory).init(any(KeyStore.class));

        assertThatThrownBy(() -> TrustManagerUtils.createTrustManager(trustStore, trustManagerFactory))
                .isInstanceOf(GenericSecurityException.class)
                .hasMessage("java.security.KeyStoreException: KABOOOM!");
    }

    @Test
    void throwGenericTrustManagerExceptionWhenProvidingEmptyListOfTrustManagersWhenCombining() {
        List<X509TrustManager> trustManagers = Collections.emptyList();
        assertThatThrownBy(() -> TrustManagerUtils.combine(trustManagers))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("Input does not contain TrustManager");
    }

    @Test
    void throwExceptionWhenUnsupportedTrustManagerIsProvidedWhenSwappingTrustManager() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager trustManagerOne = TrustManagerUtils.createTrustManager(trustStoreOne);
        X509ExtendedTrustManager trustManagerTwo = TrustManagerUtils.createTrustManager(trustStoreTwo);

        assertThatThrownBy(() -> TrustManagerUtils.swapTrustManager(trustManagerOne, trustManagerTwo))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("The baseTrustManager is from the instance of [sun.security.ssl.X509TrustManagerImpl] " +
                        "and should be an instance of [nl.altindag.ssl.trustmanager.HotSwappableX509ExtendedTrustManager].");
    }

    @Test
    void throwExceptionWhenInflatableX509ExtendedTrustManagerIsProvidedWhenSwappingTrustManager() {
        assertThatThrownBy(() -> TrustManagerUtils.swapTrustManager(mock(InflatableX509ExtendedTrustManager.class), null))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("The baseTrustManager is from the instance of [nl.altindag.ssl.trustmanager.InflatableX509ExtendedTrustManager] " +
                        "and should be an instance of [nl.altindag.ssl.trustmanager.HotSwappableX509ExtendedTrustManager].");
    }

    @Test
    void throwExceptionWhenNewTrustManagerIsHotSwappableX509ExtendedTrustManager() {
        assertThatThrownBy(() -> TrustManagerUtils.swapTrustManager(mock(HotSwappableX509ExtendedTrustManager.class), mock(HotSwappableX509ExtendedTrustManager.class)))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("The newTrustManager should not be an instance of [nl.altindag.ssl.trustmanager.HotSwappableX509ExtendedTrustManager]");
    }

    @Test
    void throwExceptionWhenNewTrustManagerIsSubClassOfHotSwappableX509ExtendedTrustManager() {
        X509ExtendedTrustManager trustManager = TrustManagerUtils.trustManagerBuilder()
                .withTrustStores(KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD))
                .withSwappableTrustManager(true)
                .build();

        assertThat(trustManager).isInstanceOf(HotSwappableX509ExtendedTrustManager.class);
        assertThat(trustManager.getAcceptedIssuers()).hasSize(1);

        class TempTrustManager extends HotSwappableX509ExtendedTrustManager {
            public TempTrustManager(X509ExtendedTrustManager trustManager) {
                super(trustManager);
            }
        }

        X509ExtendedTrustManager newTrustManager = new TempTrustManager(TrustManagerUtils.createTrustManagerWithJdkTrustedCertificates());

        assertThatThrownBy(() -> TrustManagerUtils.swapTrustManager(trustManager, newTrustManager))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("The newTrustManager should not be an instance of [nl.altindag.ssl.trustmanager.HotSwappableX509ExtendedTrustManager]");
    }

    @Test
    void throwExceptionWhenAddingCertificateToANonInflatableX509ExtendedTrustManager() {
        X509Certificate certificate = mock(X509Certificate.class);
        List<X509Certificate> certificates = Collections.singletonList(certificate);
        X509ExtendedTrustManager trustManager = mock(X509ExtendedTrustManager.class);

        assertThatThrownBy(() -> TrustManagerUtils.addCertificate(trustManager, certificates))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("The provided trustManager should be an instance of [nl.altindag.ssl.trustmanager.InflatableX509ExtendedTrustManager]");
    }

    @Test
    void throwExceptionWhenAddingCertificateToANonInflatableX509ExtendedTrustManagerEvenThoughItIsWrappedInAHotSwappableX509ExtendedTrustManager() {
        X509Certificate certificate = mock(X509Certificate.class);
        List<X509Certificate> certificates = Collections.singletonList(certificate);
        X509ExtendedTrustManager trustManager = mock(X509ExtendedTrustManager.class);
        HotSwappableX509ExtendedTrustManager hotSwappableX509ExtendedTrustManager = mock(HotSwappableX509ExtendedTrustManager.class);
        when(hotSwappableX509ExtendedTrustManager.getInnerTrustManager()).thenReturn(trustManager);

        assertThatThrownBy(() -> TrustManagerUtils.addCertificate(hotSwappableX509ExtendedTrustManager, certificates))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("The provided trustManager should be an instance of [nl.altindag.ssl.trustmanager.InflatableX509ExtendedTrustManager]");
    }

    @Test
    void throwExceptionWhenAddingCertificateToANonInflatableX509ExtendedTrustManagerEvenThoughItIsWrappedInAHotSwappableX509ExtendedTrustManagerContainingAAggregatedX509ExtendedTrustManager() {
        X509Certificate certificate = mock(X509Certificate.class);
        List<X509Certificate> certificates = Collections.singletonList(certificate);
        X509ExtendedTrustManager nonInflatableTrustManager = mock(X509ExtendedTrustManager.class);
        AggregatedX509ExtendedTrustManager aggregatedX509ExtendedTrustManager = mock(AggregatedX509ExtendedTrustManager.class);
        HotSwappableX509ExtendedTrustManager hotSwappableX509ExtendedTrustManager = mock(HotSwappableX509ExtendedTrustManager.class);
        when(hotSwappableX509ExtendedTrustManager.getInnerTrustManager()).thenReturn(aggregatedX509ExtendedTrustManager);
        when(aggregatedX509ExtendedTrustManager.getInnerTrustManagers()).thenReturn(Collections.singletonList(nonInflatableTrustManager));

        assertThatThrownBy(() -> TrustManagerUtils.addCertificate(hotSwappableX509ExtendedTrustManager, certificates))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("The provided trustManager should be an instance of [nl.altindag.ssl.trustmanager.InflatableX509ExtendedTrustManager]");
    }

    @Test
    void throwExceptionWhenAddingCertificateToANonInflatableX509ExtendedTrustManagerEvenThoughItIsWrappedInAAggregatedX509ExtendedTrustManager() {
        X509Certificate certificate = mock(X509Certificate.class);
        List<X509Certificate> certificates = Collections.singletonList(certificate);
        X509ExtendedTrustManager trustManager = mock(X509ExtendedTrustManager.class);
        AggregatedX509ExtendedTrustManager aggregatedX509ExtendedTrustManager = mock(AggregatedX509ExtendedTrustManager.class);
        when(aggregatedX509ExtendedTrustManager.getInnerTrustManagers()).thenReturn(Collections.singletonList(trustManager));

        assertThatThrownBy(() -> TrustManagerUtils.addCertificate(aggregatedX509ExtendedTrustManager, certificates))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("The provided trustManager should be an instance of [nl.altindag.ssl.trustmanager.InflatableX509ExtendedTrustManager]");
    }

    @Test
    void throwExceptionWhenUnsupportedTrustManagerIsProvidedWhenSwappingTrustManagerWithANewTrustManager() {
        KeyStore trustStoreOne = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + TRUSTSTORE_FILE_NAME, TRUSTSTORE_PASSWORD);
        KeyStore trustStoreTwo = KeyStoreUtils.loadKeyStore(KEYSTORE_LOCATION + "truststore-containing-github.jks", TRUSTSTORE_PASSWORD);

        X509ExtendedTrustManager baseTrustManager = TrustManagerUtils.createSwappableTrustManager(TrustManagerUtils.createTrustManager(trustStoreOne));
        X509ExtendedTrustManager newTrustManager = TrustManagerUtils.createSwappableTrustManager(TrustManagerUtils.createTrustManager(trustStoreTwo));

        assertThatThrownBy(() -> TrustManagerUtils.swapTrustManager(baseTrustManager, newTrustManager))
                .isInstanceOf(GenericTrustManagerException.class)
                .hasMessage("The newTrustManager should not be an instance of [nl.altindag.ssl.trustmanager.HotSwappableX509ExtendedTrustManager]");
    }

    private void resetOsName() {
        System.setProperty("os.name", ORIGINAL_OS_NAME);
    }

}
