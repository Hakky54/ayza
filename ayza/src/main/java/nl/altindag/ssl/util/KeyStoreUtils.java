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

import nl.altindag.ssl.exception.GenericKeyStoreException;
import nl.altindag.ssl.util.internal.CollectorsUtils;
import nl.altindag.ssl.util.internal.IOUtils;
import nl.altindag.ssl.util.internal.StringUtils;
import nl.altindag.yaslf4j.Logger;
import nl.altindag.yaslf4j.LoggerFactory;

import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.UnaryOperator;

import static nl.altindag.ssl.util.internal.ValidationUtils.requireNotEmpty;
import static nl.altindag.ssl.util.internal.ValidationUtils.requireNotNull;

/**
 * @author Hakan Altindag
 */
public final class KeyStoreUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyStoreUtils.class);

    public static final String DUMMY_PASSWORD = "dummy-password";
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String EMPTY_INPUT_STREAM_EXCEPTION_MESSAGE = "Failed to load the keystore from the provided InputStream because it is null";
    private static final UnaryOperator<String> KEYSTORE_NOT_FOUND_EXCEPTION_MESSAGE = certificatePath -> String.format("Failed to load the keystore from the classpath for the given path: [%s]", certificatePath);
    private static final String EMPTY_TRUST_MANAGER_FOR_TRUSTSTORE_EXCEPTION = "Could not create TrustStore because the provided TrustManager does not contain any trusted certificates";
    private static final String EMPTY_CERTIFICATES_EXCEPTION = "Could not create TrustStore because certificate is absent";

    private KeyStoreUtils() {}

    public static KeyStore loadKeyStore(String keystorePath, char[] keystorePassword) {
        return loadKeyStore(keystorePath, keystorePassword, KeyStore.getDefaultType());
    }

    public static KeyStore loadKeyStore(String keystorePath, char[] keystorePassword, String keystoreType) {
        return loadKeyStore(keystorePath, keystorePassword, keystoreType, (String) null);
    }

    public static KeyStore loadKeyStore(String keystorePath, char[] keystorePassword, String keystoreType, String providerName) {
        return loadKeyStore(keystorePath, keystoreInputStream -> loadKeyStore(keystoreInputStream, keystorePassword, keystoreType, providerName));
    }

    public static KeyStore loadKeyStore(String keystorePath, char[] keystorePassword, String keystoreType, Provider provider) {
        return loadKeyStore(keystorePath, keystoreInputStream -> loadKeyStore(keystoreInputStream, keystorePassword, keystoreType, provider));
    }

    private static KeyStore loadKeyStore(String keystorePath, KeyStoreFunction<InputStream, KeyStore> keyStoreKeyStoreFunction) {
        try (InputStream keystoreInputStream = KeyStoreUtils.class.getClassLoader().getResourceAsStream(keystorePath)) {
            requireNotNull(keystoreInputStream, KEYSTORE_NOT_FOUND_EXCEPTION_MESSAGE.apply(keystorePath));
            return keyStoreKeyStoreFunction.apply(keystoreInputStream);
        } catch (Exception e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static KeyStore loadKeyStore(Path keystorePath, char[] keystorePassword) {
        return loadKeyStore(keystorePath, keystorePassword, KeyStore.getDefaultType());
    }

    public static KeyStore loadKeyStore(Path keystorePath, char[] keystorePassword, String keystoreType) {
        return loadKeyStore(keystorePath, keystorePassword, keystoreType, (String) null);
    }

    public static KeyStore loadKeyStore(Path keystorePath, char[] keystorePassword, String keystoreType, String providerName) {
        return loadKeyStore(keystorePath, keystoreInputStream -> loadKeyStore(keystoreInputStream, keystorePassword, keystoreType, providerName));
    }

    public static KeyStore loadKeyStore(Path keystorePath, char[] keystorePassword, String keystoreType, Provider provider) {
        return loadKeyStore(keystorePath, keystoreInputStream -> loadKeyStore(keystoreInputStream, keystorePassword, keystoreType, provider));
    }

    private static KeyStore loadKeyStore(Path keystorePath, KeyStoreFunction<InputStream, KeyStore> mapper) {
        try (InputStream keystoreInputStream = Files.newInputStream(keystorePath, StandardOpenOption.READ)) {
            return mapper.apply(keystoreInputStream);
        } catch (Exception e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static KeyStore loadKeyStore(InputStream keystoreInputStream, char[] keystorePassword) {
        return loadKeyStore(
                requireNotNull(keystoreInputStream, EMPTY_INPUT_STREAM_EXCEPTION_MESSAGE),
                keystorePassword,
                KeyStore.getDefaultType()
        );
    }

    public static KeyStore loadKeyStore(InputStream keystoreInputStream, char[] keystorePassword, String keystoreType) {
        return loadKeyStore(keystoreInputStream, keystorePassword, keystoreType, (String) null);
    }

    public static KeyStore loadKeyStore(InputStream keystoreInputStream, char[] keystorePassword, String keystoreType, String providerName) {
        return loadKeyStore(keystoreInputStream, keystorePassword, () -> StringUtils.isBlank(providerName) ? KeyStore.getInstance(keystoreType) : KeyStore.getInstance(keystoreType, providerName));
    }

    public static KeyStore loadKeyStore(InputStream keystoreInputStream, char[] keystorePassword, String keystoreType, Provider provider) {
        return loadKeyStore(keystoreInputStream, keystorePassword, () -> provider == null ? KeyStore.getInstance(keystoreType) : KeyStore.getInstance(keystoreType, provider));
    }

    private static KeyStore loadKeyStore(InputStream keystoreInputStream, char[] keystorePassword, KeyStoreSupplier keyStoreSupplier) {
        try {
            KeyStore keystore = keyStoreSupplier.get();
            keystore.load(requireNotNull(keystoreInputStream, EMPTY_INPUT_STREAM_EXCEPTION_MESSAGE), keystorePassword);
            return keystore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | NoSuchProviderException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static KeyStore createIdentityStore(Key privateKey, char[] privateKeyPassword, String alias, List<? extends Certificate> certificateChain) {
        return createIdentityStore(privateKey, privateKeyPassword, alias, certificateChain.toArray(new Certificate[]{}));
    }

    public static KeyStore createIdentityStore(Key privateKey, char[] privateKeyPassword, List<? extends Certificate> certificateChain) {
        return createIdentityStore(privateKey, privateKeyPassword, null, certificateChain.toArray(new Certificate[]{}));
    }

    @SafeVarargs
    public static <T extends Certificate> KeyStore createIdentityStore(Key privateKey, char[] privateKeyPassword, T... certificateChain) {
        return createIdentityStore(privateKey, privateKeyPassword, null, certificateChain);
    }

    @SafeVarargs
    public static <T extends Certificate> KeyStore createIdentityStore(Key privateKey, char[] privateKeyPassword, String alias, T... certificateChain) {
        try {
            KeyStore keyStore = createKeyStore();
            String privateKeyAlias = StringUtils.isBlank(alias) ? CertificateUtils.generateAlias(certificateChain[0]) : alias;
            keyStore.setKeyEntry(privateKeyAlias, privateKey, privateKeyPassword, certificateChain);
            return keyStore;
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static KeyStore createKeyStore() {
        return createKeyStore(DUMMY_PASSWORD.toCharArray());
    }

    public static KeyStore createKeyStore(char[] keyStorePassword) {
        return createKeyStore(KEYSTORE_TYPE, keyStorePassword);
    }

    public static KeyStore createKeyStore(String keyStoreType, char[] keyStorePassword) {
        try {
            KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(null, keyStorePassword);
            return keyStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    @SafeVarargs
    public static <T extends X509TrustManager> KeyStore createTrustStore(T... trustManagers) {
        List<X509Certificate> certificates = new ArrayList<>();
        for (T trustManager : trustManagers) {
            certificates.addAll(Arrays.asList(trustManager.getAcceptedIssuers()));
        }

        return createTrustStore(
                requireNotEmpty(certificates, EMPTY_TRUST_MANAGER_FOR_TRUSTSTORE_EXCEPTION)
        );
    }

    @SafeVarargs
    public static <T extends Certificate> KeyStore createTrustStore(T... certificates) {
        return createTrustStore(Arrays.asList(certificates));
    }

    public static <T extends Certificate> KeyStore createTrustStore(List<T> certificates) {
        try {
            KeyStore trustStore = createKeyStore();
            for (T certificate : requireNotEmpty(certificates, EMPTY_CERTIFICATES_EXCEPTION)) {
                String alias = CertificateUtils.generateAlias(certificate);
                boolean shouldAddCertificate = true;

                if (trustStore.containsAlias(alias)) {
                    for (int number = 0; number <= 1000; number++) {
                        String mayBeUniqueAlias = alias + "-" + number;
                        if (!trustStore.containsAlias(mayBeUniqueAlias)) {
                            alias = mayBeUniqueAlias;
                            shouldAddCertificate = true;
                            break;
                        } else {
                            shouldAddCertificate = false;
                        }
                    }
                }

                if (shouldAddCertificate) {
                    trustStore.setCertificateEntry(alias, certificate);
                }
            }
            return trustStore;
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static KeyStore loadJdkKeyStore() {
        List<X509Certificate> certificates = CertificateUtils.getJdkTrustedCertificates();
        return createTrustStore(certificates);
    }

    public static List<KeyStore> loadSystemKeyStores() {
        List<KeyStore> keyStores = OperatingSystem.get().getTrustStores();
        if (LOGGER.isDebugEnabled()) {
            int totalTrustedCertificates = keyStores.stream()
                    .mapToInt(KeyStoreUtils::countAmountOfTrustMaterial)
                    .sum();

            LOGGER.debug(String.format("Loaded [%d] system trusted certificates", totalTrustedCertificates));
        }

        return Collections.unmodifiableList(keyStores);
    }

    public static KeyStore loadSystemPropertyDerivedKeyStore() {
        return loadSystemPropertyDerivedKeyStore(
                "javax.net.ssl.keyStore",
                "javax.net.ssl.keyStorePassword",
                "javax.net.ssl.keyStoreType",
                "javax.net.ssl.keyStoreProvider"
        );
    }

    public static KeyStore loadSystemPropertyDerivedTrustStore() {
        return loadSystemPropertyDerivedKeyStore(
                "javax.net.ssl.trustStore",
                "javax.net.ssl.trustStorePassword",
                "javax.net.ssl.trustStoreType",
                "javax.net.ssl.trustStoreProvider"
        );
    }

    private static KeyStore loadSystemPropertyDerivedKeyStore(String keyStorePathProperty,
                                                              String keyStorePasswordProperty,
                                                              String keyStoreTypeProperty,
                                                              String keyStoreProviderProperty) {

        Path keyStorePath = Optional.ofNullable(System.getProperty(keyStorePathProperty))
                .map(String::trim)
                .filter(StringUtils::isNotBlank)
                .map(Paths::get)
                .orElseThrow(() -> new GenericKeyStoreException(String.format("The value for the system property [%s] is absent", keyStorePathProperty)));

        char[] keystorePassword = Optional.ofNullable(System.getProperty(keyStorePasswordProperty))
                .map(String::trim)
                .filter(StringUtils::isNotBlank)
                .map(String::toCharArray)
                .orElse(null);

        String keystoreType = Optional.ofNullable(System.getProperty(keyStoreTypeProperty))
                .map(String::trim)
                .filter(StringUtils::isNotBlank)
                .orElseGet(KeyStore::getDefaultType);

        String keyStoreProvider = Optional.ofNullable(System.getProperty(keyStoreProviderProperty))
                .map(String::trim)
                .filter(StringUtils::isNotBlank)
                .orElse(null);

        return KeyStoreUtils.loadKeyStore(keyStorePath, keystorePassword, keystoreType, keyStoreProvider);
    }

    public static List<Certificate> getCertificates(KeyStore keyStore) {
        return getAliasToCertificate(keyStore).values().stream()
                .collect(CollectorsUtils.toUnmodifiableList());
    }

    public static Map<String, Certificate> getAliasToCertificate(KeyStore keyStore) {
        try {
            Map<String, Certificate> aliasToCertificate = new HashMap<>();

            List<String> aliases = getAliases(keyStore);
            for (String alias : aliases) {
                if (keyStore.isCertificateEntry(alias)) {
                    Certificate certificate = keyStore.getCertificate(alias);
                    aliasToCertificate.put(alias, certificate);
                }
            }

            return Collections.unmodifiableMap(aliasToCertificate);
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static List<String> getAliases(KeyStore keyStore) {
        try {
            List<String> destinationAliases = new ArrayList<>();
            Enumeration<String> sourceAliases = keyStore.aliases();
            while (sourceAliases.hasMoreElements()) {
                String alias = sourceAliases.nextElement();
                destinationAliases.add(alias);
            }

            return Collections.unmodifiableList(destinationAliases);
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static <T extends Certificate> boolean containsCertificate(KeyStore keyStore, T certificate) {
        try {
            return keyStore.getCertificateAlias(certificate) != null;
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static void write(Path destination, KeyStore keyStore, char[] password) {
        IOUtils.write(destination, outputStream -> keyStore.store(outputStream, password));
    }

    /**
     * Adds the provides list of certificates to the given keystore path on the filesystem if exists.
     * If the keystore is absent it will create it with the given password and also add the certificates.
     */
    public static <T extends Certificate> void add(Path keystorePath, char[] password, String keystoreType, List<T> certificates) {
        KeyStore keyStore = Files.exists(keystorePath) ? loadKeyStore(keystorePath, password, keystoreType) : createKeyStore(keystoreType, password);
        int initialAmountOfTrustMaterial = countAmountOfTrustMaterial(keyStore);

        add(keyStore, certificates);

        int amountOfTrustMaterial = countAmountOfTrustMaterial(keyStore);
        if (amountOfTrustMaterial > initialAmountOfTrustMaterial) {
            write(keystorePath, keyStore, password);
        }
    }

    public static <T extends Certificate> void add(KeyStore keyStore, List<T> certificates) {
        List<Certificate> existingCertificates = getCertificates(keyStore);
        Map<String, T> aliasToCertificate = certificates.stream()
                .distinct()
                .filter(certificate -> !existingCertificates.contains(certificate))
                .collect(CollectorsUtils.toListAndThen(CertificateUtils::generateAliases));

        String alias = "";
        try {
            for (Map.Entry<String, T> entry : aliasToCertificate.entrySet()) {
                alias = entry.getKey();

                keyStore.setCertificateEntry(alias, entry.getValue());
            }
        } catch (KeyStoreException e) {
            LOGGER.debug(String.format("Failed to add a certificate tagged with the alias [%s] to the keystore", alias), e);
        }
    }

    public static int countAmountOfTrustMaterial(KeyStore keyStore) {
        return amountOfSpecifiedMaterial(keyStore, KeyStore::isCertificateEntry, Integer.MAX_VALUE);
    }

    public static int countAmountOfIdentityMaterial(KeyStore keyStore) {
        return amountOfSpecifiedMaterial(keyStore, KeyStore::isKeyEntry, Integer.MAX_VALUE);
    }

    public static boolean containsTrustMaterial(KeyStore keyStore) {
        return amountOfSpecifiedMaterial(keyStore, KeyStore::isCertificateEntry, 1) > 0;
    }

    public static boolean containsIdentityMaterial(KeyStore keyStore) {
        return amountOfSpecifiedMaterial(keyStore, KeyStore::isKeyEntry, 1) > 0;
    }

    private static int amountOfSpecifiedMaterial(KeyStore keyStore,
                                                 KeyStoreBiPredicate<KeyStore, String> predicate,
                                                 int upperBoundaryForMaterialCounter) {

        try {
            int materialCounter = 0;

            List<String> aliases = getAliases(keyStore);
            for (String alias : aliases) {
                if (materialCounter < upperBoundaryForMaterialCounter && predicate.test(keyStore, alias)) {
                    materialCounter++;
                }
            }
            return materialCounter;
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    private interface KeyStoreBiPredicate<T extends KeyStore, U> {
        boolean test(T t, U u) throws KeyStoreException;
    }

    private interface KeyStoreFunction<T, R extends KeyStore> {
        R apply(T t) throws Exception;
    }

    private interface KeyStoreSupplier {
        KeyStore get() throws KeyStoreException, NoSuchProviderException;
    }

}
