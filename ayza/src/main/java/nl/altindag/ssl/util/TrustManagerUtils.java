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

import nl.altindag.ssl.exception.GenericTrustManagerException;
import nl.altindag.ssl.model.TrustManagerParameters;
import nl.altindag.ssl.trustmanager.CertificateCapturingX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.AggregatedX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.DelegatingX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.DummyX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.EnhanceableX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.HotSwappableX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.InflatableX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.JdkX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.LoggingX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.SystemX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.TrustManagerFactoryWrapper;
import nl.altindag.ssl.trustmanager.UnsafeX509ExtendedTrustManager;
import nl.altindag.ssl.trustmanager.X509TrustManagerWrapper;
import nl.altindag.ssl.util.internal.CollectorsUtils;
import nl.altindag.yaslf4j.Logger;
import nl.altindag.yaslf4j.LoggerFactory;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;

import static nl.altindag.ssl.util.internal.CollectorsUtils.toListAndThen;
import static nl.altindag.ssl.util.internal.ValidationUtils.requireNotEmpty;

/**
 * @author Hakan Altindag
 */
public final class TrustManagerUtils {

    private TrustManagerUtils() {}

    public static X509ExtendedTrustManager combine(X509TrustManager... trustManagers) {
        return combine(Arrays.asList(trustManagers));
    }

    public static X509ExtendedTrustManager combine(List<? extends X509TrustManager> trustManagers) {
        return TrustManagerUtils.trustManagerBuilder()
                .withTrustManagers(trustManagers)
                .build();
    }

    public static <T extends X509TrustManager> X509ExtendedTrustManager[] toArray(T trustManager) {
        return new X509ExtendedTrustManager[]{TrustManagerUtils.wrapIfNeeded(trustManager)};
    }

    public static X509ExtendedTrustManager createTrustManagerWithJdkTrustedCertificates() {
        return new JdkX509ExtendedTrustManager(createTrustManager((KeyStore) null));
    }

    public static Optional<X509ExtendedTrustManager> createTrustManagerWithSystemTrustedCertificates() {
        List<KeyStore> trustStores = KeyStoreUtils.loadSystemKeyStores();
        if (trustStores.isEmpty()) {
            return Optional.empty();
        }

        X509ExtendedTrustManager trustManager = createTrustManager(trustStores.toArray(new KeyStore[]{}));
        return Optional.of(new SystemX509ExtendedTrustManager(trustManager, OperatingSystem.get().name().toLowerCase()));
    }


    public static X509ExtendedTrustManager createTrustManager(List<X509Certificate> certificates) {
        KeyStore trustStore = KeyStoreUtils.createTrustStore(certificates);
        return TrustManagerUtils.createTrustManager(trustStore);
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStore... trustStores) {
        return Arrays.stream(trustStores)
                .map(TrustManagerUtils::createTrustManager)
                .collect(toListAndThen(TrustManagerUtils::combine));
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStore trustStore) {
        return createTrustManager(trustStore, TrustManagerFactory.getDefaultAlgorithm());
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStore trustStore, String trustManagerFactoryAlgorithm) {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustManagerFactoryAlgorithm);
            return createTrustManager(trustStore, trustManagerFactory);
        } catch (NoSuchAlgorithmException e) {
            throw new GenericTrustManagerException(e);
        }
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStore trustStore, String trustManagerFactoryAlgorithm, String securityProviderName) {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustManagerFactoryAlgorithm, securityProviderName);
            return createTrustManager(trustStore, trustManagerFactory);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new GenericTrustManagerException(e);
        }
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStore trustStore, String trustManagerFactoryAlgorithm, Provider securityProvider) {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustManagerFactoryAlgorithm, securityProvider);
            return createTrustManager(trustStore, trustManagerFactory);
        } catch (NoSuchAlgorithmException e) {
            throw new GenericTrustManagerException(e);
        }
    }

    public static X509ExtendedTrustManager createTrustManager(KeyStore trustStore, TrustManagerFactory trustManagerFactory) {
        try {
            trustManagerFactory.init(trustStore);
            return TrustManagerUtils.getTrustManager(trustManagerFactory);
        } catch (KeyStoreException e) {
            throw new GenericTrustManagerException(e);
        }
    }

    public static X509ExtendedTrustManager createTrustManager(ManagerFactoryParameters... managerFactoryParameters) {
        return Arrays.stream(managerFactoryParameters)
                .map(TrustManagerUtils::createTrustManager)
                .collect(toListAndThen(TrustManagerUtils::combine));
    }

    public static X509ExtendedTrustManager createTrustManager(ManagerFactoryParameters managerFactoryParameters) {
        return createTrustManager(managerFactoryParameters, TrustManagerFactory.getDefaultAlgorithm());
    }

    public static X509ExtendedTrustManager createTrustManager(ManagerFactoryParameters managerFactoryParameters, String trustManagerFactoryAlgorithm) {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustManagerFactoryAlgorithm);
            return createTrustManager(managerFactoryParameters, trustManagerFactory);
        } catch (NoSuchAlgorithmException e) {
            throw new GenericTrustManagerException(e);
        }
    }

    public static X509ExtendedTrustManager createTrustManager(ManagerFactoryParameters managerFactoryParameters, String trustManagerFactoryAlgorithm, String securityProviderName) {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustManagerFactoryAlgorithm, securityProviderName);
            return createTrustManager(managerFactoryParameters, trustManagerFactory);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new GenericTrustManagerException(e);
        }
    }

    public static X509ExtendedTrustManager createTrustManager(ManagerFactoryParameters managerFactoryParameters, String trustManagerFactoryAlgorithm, Provider securityProvider) {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(trustManagerFactoryAlgorithm, securityProvider);
            return createTrustManager(managerFactoryParameters, trustManagerFactory);
        } catch (NoSuchAlgorithmException e) {
            throw new GenericTrustManagerException(e);
        }
    }

    public static X509ExtendedTrustManager createTrustManager(ManagerFactoryParameters managerFactoryParameters, TrustManagerFactory trustManagerFactory) {
        try {
            trustManagerFactory.init(managerFactoryParameters);
            return TrustManagerUtils.getTrustManager(trustManagerFactory);
        } catch (InvalidAlgorithmParameterException e) {
            throw new GenericTrustManagerException(e);
        }
    }

    public static X509ExtendedTrustManager createUnsafeTrustManager() {
        return UnsafeX509ExtendedTrustManager.getInstance();
    }

    public static X509ExtendedTrustManager createDummyTrustManager() {
        return DummyX509ExtendedTrustManager.getInstance();
    }

    public static X509ExtendedTrustManager createLoggingTrustManager(X509TrustManager baseTrustManager) {
        return new LoggingX509ExtendedTrustManager(wrapIfNeeded(baseTrustManager));
    }

    public static X509ExtendedTrustManager createCertificateCapturingTrustManager(List<X509Certificate> certificatesCollector) {
        return createCertificateCapturingTrustManager(TrustManagerUtils.createUnsafeTrustManager(), certificatesCollector);
    }

    public static X509ExtendedTrustManager createCertificateCapturingTrustManager(X509TrustManager baseTrustManager, List<X509Certificate> certificatesCollector) {
        return new CertificateCapturingX509ExtendedTrustManager(wrapIfNeeded(baseTrustManager), certificatesCollector);
    }

    public static X509ExtendedTrustManager wrapIfNeeded(X509TrustManager trustManager) {
        if (trustManager instanceof X509ExtendedTrustManager) {
            return (X509ExtendedTrustManager) trustManager;
        } else {
            return new X509TrustManagerWrapper(trustManager);
        }
    }

    public static TrustManagerFactory createTrustManagerFactory(TrustManager trustManager) {
        return new TrustManagerFactoryWrapper(trustManager);
    }

    public static <T extends TrustManagerFactory> X509ExtendedTrustManager getTrustManager(T trustManagerFactory) {
        return Arrays.stream(trustManagerFactory.getTrustManagers())
                .filter(X509TrustManager.class::isInstance)
                .map(X509TrustManager.class::cast)
                .map(TrustManagerUtils::wrapIfNeeded)
                .collect(Collectors.collectingAndThen(Collectors.toList(), TrustManagerUtils::combine));
    }

    public static X509ExtendedTrustManager createInflatableTrustManager() {
        return new InflatableX509ExtendedTrustManager();
    }

    public static X509ExtendedTrustManager createInflatableTrustManager(Path trustStorePath,
                                                                        char[] trustStorePassword,
                                                                        String trustStoreType,
                                                                        Predicate<TrustManagerParameters> trustManagerParametersPredicate) {
        return new InflatableX509ExtendedTrustManager(trustStorePath, trustStorePassword, trustStoreType, trustManagerParametersPredicate);
    }

    /**
     * Adds a new to be trusted certificate to the existing TrustManager.
     * The provided TrustManager should be an instance of {@link InflatableX509ExtendedTrustManager}
     * and it is allowed that it is wrapped in a {@link AggregatedX509ExtendedTrustManager}
     */
    public static void addCertificate(X509ExtendedTrustManager trustManager, X509Certificate certificate) {
        addCertificate(trustManager, Collections.singletonList(certificate));
    }

    /**
     * Adds a new to be trusted certificate to the existing TrustManager.
     * The provided TrustManager should be an instance of {@link InflatableX509ExtendedTrustManager}
     * and it is allowed that it is wrapped in a {@link AggregatedX509ExtendedTrustManager}
     */
    public static void addCertificate(X509ExtendedTrustManager trustManager, List<X509Certificate> certificates) {
        boolean certificateAdded = addCertificateIfPossible(trustManager, certificates);
        if (certificateAdded) {
            return;
        }

        throw new GenericTrustManagerException(
                String.format("The provided trustManager should be an instance of [%s]", InflatableX509ExtendedTrustManager.class.getName())
        );
    }

    private static boolean addCertificateIfPossible(X509ExtendedTrustManager trustManager, List<X509Certificate> certificates) {
        if (trustManager instanceof InflatableX509ExtendedTrustManager) {
            ((InflatableX509ExtendedTrustManager) trustManager).addCertificates(certificates);
            return true;
        }

        if (trustManager instanceof DelegatingX509ExtendedTrustManager) {
            X509ExtendedTrustManager innerTrustManager = ((DelegatingX509ExtendedTrustManager) trustManager).getInnerTrustManager();
            return addCertificateIfPossible(innerTrustManager, certificates);
        }

        if (trustManager instanceof AggregatedX509ExtendedTrustManager) {
            List<X509ExtendedTrustManager> innerTrustManagers = ((AggregatedX509ExtendedTrustManager) trustManager).getInnerTrustManagers();

            Optional<InflatableX509ExtendedTrustManager> inflatableX509ExtendedTrustManager = innerTrustManagers.stream()
                    .filter(InflatableX509ExtendedTrustManager.class::isInstance)
                    .map(InflatableX509ExtendedTrustManager.class::cast)
                    .findFirst();

            if (inflatableX509ExtendedTrustManager.isPresent()) {
                return addCertificateIfPossible(inflatableX509ExtendedTrustManager.get(), certificates);
            }
        }

        return false;
    }

    /**
     * Wraps the given TrustManager into an instance of a Hot Swappable TrustManager.
     * This type of TrustManager has the capability of swapping in and out different TrustManagers at runtime.
     *
     * @param trustManager To be wrapped TrustManager
     * @return Swappable TrustManager
     */
    public static X509ExtendedTrustManager createSwappableTrustManager(X509TrustManager trustManager) {
        return new HotSwappableX509ExtendedTrustManager(TrustManagerUtils.wrapIfNeeded(trustManager));
    }

    /**
     * Swaps the internal TrustManager instance with the given trustManager object.
     * The baseTrustManager should be an instance of {@link HotSwappableX509ExtendedTrustManager}
     * and can be created with {@link TrustManagerUtils#createSwappableTrustManager(X509TrustManager)}
     *
     * @param baseTrustManager an instance of {@link HotSwappableX509ExtendedTrustManager}
     * @param newTrustManager  to be injected instance of a TrustManager
     * @throws GenericTrustManagerException if {@code baseTrustManager} is not instance of {@link HotSwappableX509ExtendedTrustManager}
     */
    public static void swapTrustManager(X509TrustManager baseTrustManager, X509TrustManager newTrustManager) {
        if (baseTrustManager instanceof InflatableX509ExtendedTrustManager) {
            throw new GenericTrustManagerException(
                    String.format("The baseTrustManager is from the instance of [%s] and should be an instance of [%s].",
                            baseTrustManager.getClass().getName(),
                            HotSwappableX509ExtendedTrustManager.class.getName())
            );
        }

        if (!(baseTrustManager instanceof HotSwappableX509ExtendedTrustManager)) {
            throw new GenericTrustManagerException(
                    String.format("The baseTrustManager is from the instance of [%s] and should be an instance of [%s].",
                            baseTrustManager.getClass().getName(),
                            HotSwappableX509ExtendedTrustManager.class.getName())
            );
        }

        if (newTrustManager instanceof HotSwappableX509ExtendedTrustManager
                && !(newTrustManager instanceof InflatableX509ExtendedTrustManager)) {
            throw new GenericTrustManagerException(
                    String.format("The newTrustManager should not be an instance of [%s]", HotSwappableX509ExtendedTrustManager.class.getName())
            );
        }

        HotSwappableX509ExtendedTrustManager swappableTrustManager = (HotSwappableX509ExtendedTrustManager) baseTrustManager;
        X509ExtendedTrustManager innerTrustManager = swappableTrustManager.getInnerTrustManager();

        List<UnaryOperator<X509ExtendedTrustManager>> mappers = new ArrayList<>();
        computeMappersForNewTrustManager(innerTrustManager, mappers);
        Collections.reverse(mappers);

        X509ExtendedTrustManager resolvedNewTrustManager = TrustManagerUtils.wrapIfNeeded(newTrustManager);
        for (UnaryOperator<X509ExtendedTrustManager> mapper : mappers) {
            resolvedNewTrustManager = mapper.apply(resolvedNewTrustManager);
        }

        swappableTrustManager.setTrustManager(resolvedNewTrustManager);
    }

    private static void computeMappersForNewTrustManager(X509ExtendedTrustManager trustManager, List<UnaryOperator<X509ExtendedTrustManager>> mappers) {
        if (trustManager instanceof LoggingX509ExtendedTrustManager) {
            LoggingX509ExtendedTrustManager loggingTrustManager = (LoggingX509ExtendedTrustManager) trustManager;
            mappers.add(LoggingX509ExtendedTrustManager::new);
            computeMappersForNewTrustManager(loggingTrustManager.getInnerTrustManager(), mappers);
        }

        if (trustManager instanceof EnhanceableX509ExtendedTrustManager) {
            EnhanceableX509ExtendedTrustManager existingEnhanceableTrustManager = (EnhanceableX509ExtendedTrustManager) trustManager;
            mappers.add(newTrustManager ->
                    new EnhanceableX509ExtendedTrustManager(
                            TrustManagerUtils.wrapIfNeeded(newTrustManager),
                            existingEnhanceableTrustManager.getTrustManagerParametersValidator(),
                            existingEnhanceableTrustManager.isTrustedCertificatesConcealed()
                    )
            );
            computeMappersForNewTrustManager(existingEnhanceableTrustManager.getInnerTrustManager(), mappers);
        }
    }

    public static X509ExtendedTrustManager createEnhanceableTrustManager(
            X509ExtendedTrustManager trustManager,
            Predicate<TrustManagerParameters> trustManagerParametersValidator) {

        return createEnhanceableTrustManager(trustManager, trustManagerParametersValidator, false);
    }

    public static X509ExtendedTrustManager createEnhanceableTrustManager(
            X509ExtendedTrustManager trustManager,
            Predicate<TrustManagerParameters> trustManagerParametersValidator,
            boolean shouldTrustedCertificatesBeConcealed) {

        return new EnhanceableX509ExtendedTrustManager(trustManager, trustManagerParametersValidator, shouldTrustedCertificatesBeConcealed);
    }

    private static List<X509ExtendedTrustManager> unwrapIfPossible(X509ExtendedTrustManager trustManager) {
        if (trustManager instanceof AggregatedX509ExtendedTrustManager) {
            List<X509ExtendedTrustManager> trustManagers = new ArrayList<>();
            for (X509ExtendedTrustManager innerTrustManager : ((AggregatedX509ExtendedTrustManager) trustManager).getInnerTrustManagers()) {
                List<X509ExtendedTrustManager> unwrappedTrustManagers = TrustManagerUtils.unwrapIfPossible(innerTrustManager);
                trustManagers.addAll(unwrappedTrustManagers);
            }
            return trustManagers;
        } else {
            return Collections.singletonList(trustManager);
        }
    }

    public static TrustManagerBuilder trustManagerBuilder() {
        return new TrustManagerBuilder();
    }

    public static final class TrustManagerBuilder {

        private static final Logger LOGGER = LoggerFactory.getLogger(TrustManagerBuilder.class);
        private static final String EMPTY_TRUST_MANAGER_EXCEPTION = "Input does not contain TrustManager";

        private TrustManagerBuilder() {
        }

        private final List<X509ExtendedTrustManager> trustManagers = new ArrayList<>();
        private boolean swappableTrustManagerEnabled = false;
        private boolean loggingTrustManagerEnabled = false;

        private Predicate<TrustManagerParameters> trustManagerParametersValidator;
        private boolean shouldTrustedCertificatesBeConcealed;

        public <T extends X509TrustManager> TrustManagerBuilder withTrustManagers(T... trustManagers) {
            for (T trustManager : trustManagers) {
                withTrustManager(trustManager);
            }
            return this;
        }

        public <T extends X509TrustManager> TrustManagerBuilder withTrustManagers(List<T> trustManagers) {
            for (X509TrustManager trustManager : trustManagers) {
                withTrustManager(trustManager);
            }
            return this;
        }

        public <T extends X509TrustManager> TrustManagerBuilder withTrustManager(T trustManager) {
            this.trustManagers.add(TrustManagerUtils.wrapIfNeeded(trustManager));
            return this;
        }

        public <T extends KeyStore> TrustManagerBuilder withTrustStores(T... trustStores) {
            return withTrustStores(Arrays.asList(trustStores));
        }

        public TrustManagerBuilder withTrustStores(List<? extends KeyStore> trustStores) {
            for (KeyStore trustStore : trustStores) {
                this.trustManagers.add(TrustManagerUtils.createTrustManager(trustStore));
            }
            return this;
        }

        public <T extends KeyStore> TrustManagerBuilder withTrustStore(T trustStore) {
            this.trustManagers.add(TrustManagerUtils.createTrustManager(trustStore));
            return this;
        }

        public <T extends KeyStore> TrustManagerBuilder withTrustStore(T trustStore, String trustManagerAlgorithm) {
            this.trustManagers.add(TrustManagerUtils.createTrustManager(trustStore, trustManagerAlgorithm));
            return this;
        }

        public TrustManagerBuilder withSwappableTrustManager(boolean swappableTrustManagerEnabled) {
            this.swappableTrustManagerEnabled = swappableTrustManagerEnabled;
            return this;
        }

        public TrustManagerBuilder withLoggingTrustManager(boolean loggingTrustManagerEnabled) {
            this.loggingTrustManagerEnabled = loggingTrustManagerEnabled;
            return this;
        }

        public TrustManagerBuilder withTrustEnhancer(Predicate<TrustManagerParameters> trustManagerParametersValidator) {
            this.trustManagerParametersValidator = trustManagerParametersValidator;
            return this;
        }

        public TrustManagerBuilder withTrustEnhancer(boolean shouldTrustedCertificatesBeConcealed) {
            this.shouldTrustedCertificatesBeConcealed = shouldTrustedCertificatesBeConcealed;
            return this;
        }

        public X509ExtendedTrustManager build() {
            requireNotEmpty(trustManagers, () -> new GenericTrustManagerException(EMPTY_TRUST_MANAGER_EXCEPTION));

            X509ExtendedTrustManager baseTrustManager;
            Optional<X509ExtendedTrustManager> unsafeOrDummyTrustManager = getUnsafeOrDummyTrustManagerIfConfigured(trustManagers);
            if (unsafeOrDummyTrustManager.isPresent()) {
                baseTrustManager = unsafeOrDummyTrustManager.get();
            } else {
                baseTrustManager = combine(trustManagers);
                baseTrustManager = createEnhanceableTrustManagerIfEnabled(baseTrustManager)
                        .orElse(baseTrustManager);
            }

            if (loggingTrustManagerEnabled) {
                baseTrustManager = TrustManagerUtils.createLoggingTrustManager(baseTrustManager);
            }

            if (swappableTrustManagerEnabled) {
                baseTrustManager = TrustManagerUtils.createSwappableTrustManager(baseTrustManager);
            }

            return baseTrustManager;
        }

        private Optional<X509ExtendedTrustManager> getUnsafeOrDummyTrustManagerIfConfigured(List<X509ExtendedTrustManager> trustManagers) {
            Optional<X509ExtendedTrustManager> maybeUnsafeTrustManager = trustManagers.stream()
                    .filter(UnsafeX509ExtendedTrustManager.class::isInstance)
                    .findAny();

            if (maybeUnsafeTrustManager.isPresent()) {
                if (trustManagers.size() > 1) {
                    LOGGER.debug("Unsafe TrustManager is being used therefore other trust managers will not be included for constructing the base trust manager");
                }

                return maybeUnsafeTrustManager;
            }

            Optional<X509ExtendedTrustManager> maybeDummyTrustManager = trustManagers.stream()
                    .filter(DummyX509ExtendedTrustManager.class::isInstance)
                    .findAny();

            if (maybeDummyTrustManager.isPresent()) {
                if (trustManagers.size() > 1) {
                    LOGGER.debug("Dummy TrustManager is being used therefore other trust managers will not be included for constructing the base trust manager");
                }

                return maybeDummyTrustManager;
            }

            return Optional.empty();
        }

        private X509ExtendedTrustManager combine(List<X509ExtendedTrustManager> trustManagers) {
            if (trustManagers.size() == 1) {
                return trustManagers.get(0);
            }

            return trustManagers.stream()
                    .map(TrustManagerUtils::unwrapIfPossible)
                    .flatMap(Collection::stream)
                    .collect(CollectorsUtils.toListAndThen(AggregatedX509ExtendedTrustManager::new));
        }

        private Optional<X509ExtendedTrustManager> createEnhanceableTrustManagerIfEnabled(X509ExtendedTrustManager baseTrustManager) {
            if (trustManagerParametersValidator == null && !shouldTrustedCertificatesBeConcealed) {
                return Optional.empty();
            }

            Predicate<TrustManagerParameters> aTrustManagerParametersValidator;
            if (trustManagerParametersValidator != null) {
                aTrustManagerParametersValidator = trustManagerParametersValidator;
            } else {
                aTrustManagerParametersValidator = trustManagerParameters -> false;
            }

            X509ExtendedTrustManager enhanceableTrustManager = TrustManagerUtils.createEnhanceableTrustManager(baseTrustManager, aTrustManagerParametersValidator, shouldTrustedCertificatesBeConcealed);
            return Optional.of(enhanceableTrustManager);
        }

    }

}
