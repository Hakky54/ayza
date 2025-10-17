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
package nl.altindag.ssl.trustmanager;

import nl.altindag.ssl.exception.GenericKeyStoreException;
import nl.altindag.ssl.model.TrustManagerParameters;
import nl.altindag.ssl.util.CertificateUtils;
import nl.altindag.ssl.util.KeyStoreUtils;
import nl.altindag.ssl.util.TrustManagerUtils;
import nl.altindag.ssl.util.internal.StringUtils;
import nl.altindag.sude.Logger;
import nl.altindag.sude.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.BiPredicate;
import java.util.function.Predicate;

import static nl.altindag.ssl.util.internal.CollectionUtils.isEmpty;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.TrustManagerUtils TrustManagerUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 * <p>
 * The Inflatable TrustManager has the capability to grow with newly trusted certificates at any moment in time.
 * It can be either added manually with {@link TrustManagerUtils#addCertificate(X509ExtendedTrustManager, List)} or by providing
 * a predicate in the constructor of this class so it can evaluate every certificate whether it should be trusted or not.
 * Next to that it will write the trusted certificates to the file system as a keystore file if the properties are provided in the
 * constructor. If this is not the case it will still use an in-memory keystore to maintain the newly added certificates, however
 * the state will get lost when the application has been restarted.
 *
 * @author Hakan Altindag
 */
public class InflatableX509ExtendedTrustManager extends HotSwappableX509ExtendedTrustManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(InflatableX509ExtendedTrustManager.class);
    private static final BiPredicate<KeyStore, X509Certificate> IGNORE_DUPLICATE_CHECKER = (t, c) -> false;

    private final KeyStore trustStore;
    private final Path trustStorePath;
    private final char[] trustStorePassword;
    private final Predicate<TrustManagerParameters> trustManagerParametersPredicate;

    public InflatableX509ExtendedTrustManager() {
        this(null, null, null, null);
    }

    public InflatableX509ExtendedTrustManager(Path trustStorePath,
                                              char[] trustStorePassword,
                                              String trustStoreType,
                                              Predicate<TrustManagerParameters> trustManagerParametersPredicate) {

        super(TrustManagerUtils.createDummyTrustManager());

        writeLock.lock();

        try {
            this.trustStorePath = trustStorePath;
            this.trustStorePassword = trustStorePassword;

            this.trustManagerParametersPredicate = Optional.ofNullable(trustManagerParametersPredicate)
                    .orElse(trustManagerParameters -> false);

            if (trustStorePath != null && StringUtils.isNotBlank(trustStoreType)) {
                if (Files.exists(trustStorePath)) {
                    trustStore = KeyStoreUtils.loadKeyStore(trustStorePath, trustStorePassword, trustStoreType);
                    if (KeyStoreUtils.containsTrustMaterial(trustStore)) {
                        setTrustManager(TrustManagerUtils.createTrustManager(trustStore));
                    }
                } else {
                    trustStore = KeyStoreUtils.createKeyStore(trustStoreType, trustStorePassword);
                }
            } else {
                trustStore = KeyStoreUtils.createKeyStore();
            }
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(() -> super.checkServerTrusted(chain, authType), chain, authType, null, null);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkTrusted(() -> super.checkServerTrusted(chain, authType, socket), chain, authType, socket, null);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        checkTrusted(() -> super.checkServerTrusted(chain, authType, sslEngine), chain, authType, null, sslEngine);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(() -> super.checkClientTrusted(chain, authType), chain, authType, null, null);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkTrusted(() -> super.checkClientTrusted(chain, authType, socket), chain, authType, socket, null);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        checkTrusted(() -> super.checkClientTrusted(chain, authType, sslEngine), chain, authType, null, sslEngine);
    }

    private void checkTrusted(TrustManagerRunnable trustManagerRunnable, X509Certificate[] chain, String authType, Socket socket, SSLEngine sslEngine) throws CertificateException {
        try {
            // Use a read lock first in order to be more efficient
            readLock.lock();
            try {
                trustManagerRunnable.run();
            } finally {
                readLock.unlock();
            }
        } catch (CertificateException e) {
            writeLock.lock();
            // Recheck in a write lock, in case of a concurrent update (kind of double-checked locking)
            try {
                trustManagerRunnable.run();
            } catch (CertificateException e2) {
                TrustManagerParameters trustManagerParameters = new TrustManagerParameters(chain, authType, socket, sslEngine);
                boolean shouldBeTrusted = trustManagerParametersPredicate.test(trustManagerParameters);
                if (shouldBeTrusted) {
                    addCertificates(Collections.singletonList(chain[0]), IGNORE_DUPLICATE_CHECKER);
                } else {
                    throw e2;
                }
            } finally {
                writeLock.unlock();
            }
        }
    }

    public void addCertificates(List<X509Certificate> certificates) {
        addCertificates(certificates, KeyStoreUtils::containsCertificate);
    }

    private void addCertificates(List<X509Certificate> certificates, BiPredicate<KeyStore, X509Certificate> duplicateChecker) {
        writeLock.lock();

        try {
            if (isEmpty(certificates)) {
                return;
            }

            for (X509Certificate certificate : certificates) {
                if (duplicateChecker.test(trustStore, certificate)) {
                    continue;
                }

                String alias = generateAlias(certificate);
                trustStore.setCertificateEntry(alias, certificate);
                LOGGER.info(String.format("Added certificate for [%s]", alias));
            }
            X509ExtendedTrustManager trustManager = TrustManagerUtils.createTrustManager(trustStore);
            setTrustManager(trustManager);
            getTrustStorePath().ifPresent(path -> KeyStoreUtils.write(path, trustStore, trustStorePassword));
        } catch (KeyStoreException | GenericKeyStoreException e) {
            LOGGER.error("Cannot add certificate", e);
        } finally {
            writeLock.unlock();
        }
    }

    private String generateAlias(Certificate certificate) {
        return CertificateUtils.generateUniqueAlias(certificate, alias -> {
            try {
                return trustStore.containsAlias(alias);
            } catch (KeyStoreException e) {
                throw new GenericKeyStoreException(e);
            }
        });
    }

    private Optional<Path> getTrustStorePath() {
        return Optional.ofNullable(trustStorePath);
    }

}
