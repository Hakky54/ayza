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

import nl.altindag.laleler.UriUtils;
import nl.altindag.ssl.exception.GenericKeyManagerException;
import nl.altindag.ssl.exception.GenericKeyStoreException;
import nl.altindag.ssl.keymanager.AggregatedX509ExtendedKeyManager;
import nl.altindag.ssl.keymanager.CombinableX509KeyManager;
import nl.altindag.ssl.keymanager.DelegatingX509ExtendedKeyManager;
import nl.altindag.ssl.keymanager.DummyX509ExtendedKeyManager;
import nl.altindag.ssl.keymanager.HotSwappableX509ExtendedKeyManager;
import nl.altindag.ssl.keymanager.InflatableX509ExtendedKeyManager;
import nl.altindag.ssl.keymanager.KeyManagerFactoryWrapper;
import nl.altindag.ssl.keymanager.LoggingX509ExtendedKeyManager;
import nl.altindag.ssl.keymanager.X509KeyManagerWrapper;
import nl.altindag.ssl.model.KeyStoreHolder;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
import java.net.URI;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import static nl.altindag.laleler.CollectionUtils.toUnmodifiableList;
import static nl.altindag.laleler.CollectorsUtils.toListAndThen;
import static nl.altindag.laleler.CollectorsUtils.toMapAndThen;
import static nl.altindag.laleler.CollectorsUtils.toUnmodifiableList;
import static nl.altindag.laleler.ValidationUtils.GENERIC_EXCEPTION_MESSAGE;
import static nl.altindag.laleler.ValidationUtils.requireNotEmpty;
import static nl.altindag.laleler.ValidationUtils.requireNotNull;

/**
 * @author Hakan Altindag
 */
public final class KeyManagerUtils {

    private static final char[] DUMMY_PASSWORD = KeyStoreUtils.DUMMY_PASSWORD.toCharArray();
    private static final BiFunction<Class<?>, Class<?>, GenericKeyManagerException> KEY_MANAGER_TYPE_MISMATCH_EXCEPTION_PROVIDER = (expectedKeyManagerType, actualKeyManagerType) -> new GenericKeyManagerException(
            String.format(
                    "KeyManager should be an instance of: [%s], but received: [%s]",
                    expectedKeyManagerType.getName(),
                    actualKeyManagerType.getName())
    );

    private KeyManagerUtils() {}

    public static X509ExtendedKeyManager combine(X509KeyManager... keyManagers) {
        return combine(Arrays.asList(keyManagers));
    }

    public static X509ExtendedKeyManager combine(List<? extends X509KeyManager> keyManagers) {
        return KeyManagerUtils.keyManagerBuilder()
                .withKeyManagers(keyManagers)
                .build();
    }

    public static <T extends X509KeyManager> X509ExtendedKeyManager[] toArray(T keyManager) {
        return new X509ExtendedKeyManager[]{KeyManagerUtils.wrapIfNeeded(keyManager)};
    }

    public static X509ExtendedKeyManager createKeyManager(KeyStoreHolder... keyStoreHolders) {
        return Arrays.stream(keyStoreHolders)
                .map(keyStoreHolder -> createKeyManager(keyStoreHolder.getKeyStore(), keyStoreHolder.getKeyPassword()))
                .collect(toListAndThen(KeyManagerUtils::combine));
    }

    public static X509ExtendedKeyManager createKeyManager(KeyStore keyStore, char[] keyPassword) {
        return createKeyManager(keyStore, keyPassword, KeyManagerFactory.getDefaultAlgorithm());
    }

    public static X509ExtendedKeyManager createKeyManager(KeyStore keyStore, char[] keyPassword, String keyManagerFactoryAlgorithm) {
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(keyManagerFactoryAlgorithm);
            return createKeyManager(keyStore, keyPassword, keyManagerFactory);
        } catch (NoSuchAlgorithmException e) {
            throw new GenericKeyManagerException(e);
        }
    }

    public static X509ExtendedKeyManager createKeyManager(KeyStore keyStore, char[] keyPassword, String keyManagerFactoryAlgorithm, String securityProviderName) {
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(keyManagerFactoryAlgorithm, securityProviderName);
            return createKeyManager(keyStore, keyPassword, keyManagerFactory);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new GenericKeyManagerException(e);
        }
    }

    public static X509ExtendedKeyManager createKeyManager(KeyStore keyStore, char[] keyPassword, String keyManagerFactoryAlgorithm, Provider securityProvider) {
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(keyManagerFactoryAlgorithm, securityProvider);
            return createKeyManager(keyStore, keyPassword, keyManagerFactory);
        } catch (NoSuchAlgorithmException e) {
            throw new GenericKeyManagerException(e);
        }
    }

    public static X509ExtendedKeyManager createKeyManager(KeyStore keyStore, char[] keyPassword, KeyManagerFactory keyManagerFactory) {
        try {
            keyManagerFactory.init(keyStore, keyPassword);
            return KeyManagerUtils.getKeyManager(keyManagerFactory);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new GenericKeyManagerException(e);
        }
    }

    public static X509ExtendedKeyManager createKeyManager(KeyStore keyStore, Map<String, char[]> aliasToPassword) {
        List<X509ExtendedKeyManager> keyManagers = new ArrayList<>();

        for (Entry<String, char[]> entry : aliasToPassword.entrySet()) {
            try {
                String alias = entry.getKey();
                char[] password = entry.getValue();

                if (keyStore.isKeyEntry(alias)) {
                    Key key = keyStore.getKey(alias, password);
                    Certificate[] certificateChain = keyStore.getCertificateChain(alias);

                    KeyStore identityStore = KeyStoreUtils.createIdentityStore(key, password, certificateChain);
                    X509ExtendedKeyManager keyManager = KeyManagerUtils.createKeyManager(identityStore, password);
                    keyManagers.add(keyManager);
                }
            } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                throw new GenericKeyManagerException(e);
            }
        }

        requireNotEmpty(keyManagers, () -> new GenericKeyManagerException("Could not create any KeyManager from the given KeyStore, Alias and Password"));
        return KeyManagerUtils.combine(keyManagers);
    }

    public static X509ExtendedKeyManager wrapIfNeeded(X509KeyManager keyManager) {
        if (keyManager instanceof X509ExtendedKeyManager) {
            return (X509ExtendedKeyManager) keyManager;
        } else {
            return new X509KeyManagerWrapper(keyManager);
        }
    }

    public static KeyManagerFactory createKeyManagerFactory(KeyManager keyManager) {
        return new KeyManagerFactoryWrapper(keyManager);
    }

    public static <T extends KeyManagerFactory> X509ExtendedKeyManager getKeyManager(T keyManagerFactory) {
        return Arrays.stream(keyManagerFactory.getKeyManagers())
                .filter(X509KeyManager.class::isInstance)
                .map(X509KeyManager.class::cast)
                .map(KeyManagerUtils::wrapIfNeeded)
                .collect(toListAndThen(KeyManagerUtils::combine));
    }

    public static X509ExtendedKeyManager createDummyKeyManager() {
        return DummyX509ExtendedKeyManager.getInstance();
    }

    public static X509ExtendedKeyManager createLoggingKeyManager(X509KeyManager keyManager) {
        return new LoggingX509ExtendedKeyManager(KeyManagerUtils.wrapIfNeeded(keyManager));
    }

    /**
     * Wraps the given KeyManager into an instance of a Hot Swappable KeyManager
     * This type of KeyManager has the capability of swapping in and out different KeyManagers at runtime.
     *
     * @param keyManager    To be wrapped KeyManager
     * @return              Swappable KeyManager
     */
    public static X509ExtendedKeyManager createSwappableKeyManager(X509KeyManager keyManager) {
        return new HotSwappableX509ExtendedKeyManager(KeyManagerUtils.wrapIfNeeded(keyManager));
    }

    /**
     * Swaps the internal KeyManager instance with the given keyManager object.
     * The baseKeyManager should be an instance of {@link HotSwappableX509ExtendedKeyManager}
     * and can be created with {@link KeyManagerUtils#createSwappableKeyManager(X509KeyManager)}
     *
     * @param baseKeyManager                an instance of {@link HotSwappableX509ExtendedKeyManager}
     * @param newKeyManager                 to be injected instance of a KeyManager
     * @throws GenericKeyManagerException   if {@code baseKeyManager} is not instance of {@link HotSwappableX509ExtendedKeyManager}
     */
    public static void swapKeyManager(X509KeyManager baseKeyManager, X509KeyManager newKeyManager) {
        if (newKeyManager instanceof HotSwappableX509ExtendedKeyManager) {
            throw new GenericKeyManagerException(
                    String.format("The newKeyManager should not be an instance of [%s]", HotSwappableX509ExtendedKeyManager.class.getName())
            );
        }

        if (baseKeyManager instanceof HotSwappableX509ExtendedKeyManager
                && ((HotSwappableX509ExtendedKeyManager) baseKeyManager).getInnerKeyManager() instanceof LoggingX509ExtendedKeyManager) {
            ((HotSwappableX509ExtendedKeyManager) baseKeyManager).setKeyManager(
                    new LoggingX509ExtendedKeyManager(
                            KeyManagerUtils.wrapIfNeeded(newKeyManager)
                    )
            );
        } else if (baseKeyManager instanceof HotSwappableX509ExtendedKeyManager) {
            ((HotSwappableX509ExtendedKeyManager) baseKeyManager).setKeyManager(KeyManagerUtils.wrapIfNeeded(newKeyManager));
        } else {
            throw new GenericKeyManagerException(
                    String.format("The baseKeyManager is from the instance of [%s] and should be an instance of [%s].",
                            baseKeyManager.getClass().getName(),
                            HotSwappableX509ExtendedKeyManager.class.getName())
            );
        }
    }

    public static void addIdentityRoute(X509ExtendedKeyManager keyManager, String alias, String... hosts) {
        computeIdentityRoute(keyManager, alias, hosts, false, false);
    }

    public static void overrideIdentityRoute(X509ExtendedKeyManager keyManager, String alias, String... hosts) {
        computeIdentityRoute(keyManager, alias, hosts, true, false);
    }

    public static void removeIdentityRoute(X509ExtendedKeyManager keyManager, String alias) {
        computeIdentityRoute(keyManager, alias, null, false, true);
    }

    private static void computeIdentityRoute(X509ExtendedKeyManager keyManager,
                                             String alias,
                                             String[] hosts,
                                             boolean overrideExistingRouteEnabled,
                                             boolean removeExistingRouteEnabled) {

        requireNotNull(keyManager, GENERIC_EXCEPTION_MESSAGE.apply("KeyManager"));
        requireNotNull(alias, GENERIC_EXCEPTION_MESSAGE.apply("Alias"));

        if (keyManager instanceof DelegatingX509ExtendedKeyManager) {
            computeIdentityRoute(((DelegatingX509ExtendedKeyManager) keyManager).getInnerKeyManager(), alias, hosts, overrideExistingRouteEnabled, removeExistingRouteEnabled);
            return;
        }

        if (keyManager instanceof AggregatedX509ExtendedKeyManager) {
            AggregatedX509ExtendedKeyManager aggregatedX509ExtendedKeyManager = (AggregatedX509ExtendedKeyManager) keyManager;
            Map<String, List<URI>> aliasToHosts = aggregatedX509ExtendedKeyManager.getIdentityRoute();

            if (removeExistingRouteEnabled) {
                aliasToHosts.remove(alias);
                return;
            }

            requireNotNull(hosts, GENERIC_EXCEPTION_MESSAGE.apply("Host"));
            List<URI> uris = new ArrayList<>();
            for (String host : hosts) {
                URI uri = URI.create(host);
                UriUtils.validate(uri);
                uris.add(uri);
            }

            if (overrideExistingRouteEnabled && aliasToHosts.containsKey(alias)) {
                aliasToHosts.get(alias).clear();
            }

            for (URI uri : uris) {
                if (aliasToHosts.containsKey(alias)) {
                    aliasToHosts.get(alias).add(uri);
                } else {
                    aliasToHosts.put(alias, new ArrayList<>(Collections.singleton(uri)));
                }
            }
        } else {
            throw KEY_MANAGER_TYPE_MISMATCH_EXCEPTION_PROVIDER.apply(AggregatedX509ExtendedKeyManager.class, keyManager.getClass());
        }
    }

    public static Map<String, List<String>> getIdentityRoute(X509ExtendedKeyManager keyManager) {
        requireNotNull(keyManager, GENERIC_EXCEPTION_MESSAGE.apply("KeyManager"));

        if (keyManager instanceof DelegatingX509ExtendedKeyManager) {
            return getIdentityRoute(((DelegatingX509ExtendedKeyManager) keyManager).getInnerKeyManager());
        }

        if (keyManager instanceof AggregatedX509ExtendedKeyManager) {
            return ((AggregatedX509ExtendedKeyManager) keyManager)
                    .getIdentityRoute()
                    .entrySet().stream()
                    .collect(Collectors.collectingAndThen(
                            Collectors.toMap(
                                    Entry::getKey,
                                    hosts -> hosts.getValue().stream()
                                            .map(URI::toString)
                                            .collect(toUnmodifiableList())),
                            Collections::unmodifiableMap)
                    );
        } else {
            throw KEY_MANAGER_TYPE_MISMATCH_EXCEPTION_PROVIDER.apply(AggregatedX509ExtendedKeyManager.class, keyManager.getClass());
        }
    }

    private static List<X509ExtendedKeyManager> unwrapIfPossible(X509ExtendedKeyManager keyManager) {
        if (keyManager instanceof AggregatedX509ExtendedKeyManager) {
            List<X509ExtendedKeyManager> keyManagers = new ArrayList<>();
            for (X509ExtendedKeyManager innerKeyManager : ((AggregatedX509ExtendedKeyManager) keyManager).getInnerKeyManagers().values()) {
                List<X509ExtendedKeyManager> unwrappedKeyManagers = KeyManagerUtils.unwrapIfPossible(innerKeyManager);
                keyManagers.addAll(unwrappedKeyManagers);
            }
            return keyManagers;
        } else {
            return Collections.singletonList(keyManager);
        }
    }

    public static KeyManagerBuilder keyManagerBuilder() {
        return new KeyManagerBuilder();
    }

    public static X509ExtendedKeyManager createKeyManager(PrivateKey privateKey, Certificate[] certificatesChain) {
        String alias = CertificateUtils.generateAlias(certificatesChain[0]);
        return createKeyManager(alias, privateKey, certificatesChain);
    }

    public static X509ExtendedKeyManager createKeyManager(String alias, PrivateKey privateKey, Certificate[] certificatesChain) {
        try {
            KeyStore keyStore = KeyStoreUtils.createKeyStore();
            keyStore.setKeyEntry(alias, privateKey, DUMMY_PASSWORD, certificatesChain);
            return KeyManagerUtils.createKeyManager(keyStore, DUMMY_PASSWORD);
        } catch (KeyStoreException e) {
            throw new GenericKeyStoreException(e);
        }
    }

    public static X509ExtendedKeyManager createInflatableKeyManager() {
        return new InflatableX509ExtendedKeyManager();
    }

    public static X509ExtendedKeyManager createInflatableKeyManager(String alias, X509ExtendedKeyManager keyManager) {
        return new InflatableX509ExtendedKeyManager(alias, keyManager);
    }

    /**
     * Adds identity material tp a {@link InflatableX509ExtendedKeyManager}
     * If the provided keyManager is not of the type {@link InflatableX509ExtendedKeyManager} it will throw an exception
     */
    public static void addIdentityMaterial(X509ExtendedKeyManager keyManager, String alias, KeyStore keyStore, char[] keyPassword) {
        X509ExtendedKeyManager keyManagerToBeAdded = createKeyManager(keyStore, keyPassword);
        addIdentityMaterial(keyManager, alias, keyManagerToBeAdded);
    }

    /**
     * Adds identity material tp a {@link InflatableX509ExtendedKeyManager}
     * If the provided baseKeyManager is not of the type {@link InflatableX509ExtendedKeyManager} it will throw an exception
     */
    public static void addIdentityMaterial(X509ExtendedKeyManager baseKeyManager, String alias, X509ExtendedKeyManager keyManagerToBeAdded) {
        boolean identityAdded = computeIdentityMaterialIfPossible(baseKeyManager, km -> km.addIdentity(alias, keyManagerToBeAdded));
        if (identityAdded) {
            return;
        }

        throw KEY_MANAGER_TYPE_MISMATCH_EXCEPTION_PROVIDER.apply(InflatableX509ExtendedKeyManager.class, baseKeyManager.getClass());
    }

    /**
     * Removes identity material from a {@link InflatableX509ExtendedKeyManager}
     */
    public static void removeIdentityMaterial(X509ExtendedKeyManager baseKeyManager, String alias) {
        computeIdentityMaterialIfPossible(baseKeyManager, km -> km.removeIdentity(alias));
    }

    /**
     * Remove, add or other actions related to {@link InflatableX509ExtendedKeyManager}
     */
    private static boolean computeIdentityMaterialIfPossible(X509ExtendedKeyManager baseKeyManager, Consumer<InflatableX509ExtendedKeyManager> consumer) {
        if (baseKeyManager instanceof InflatableX509ExtendedKeyManager) {

            consumer.accept((InflatableX509ExtendedKeyManager) baseKeyManager);
            return true;
        }

        if (baseKeyManager instanceof DelegatingX509ExtendedKeyManager) {
            X509ExtendedKeyManager innerKeyManager = ((DelegatingX509ExtendedKeyManager) baseKeyManager).getInnerKeyManager();
            return computeIdentityMaterialIfPossible(innerKeyManager, consumer);
        }

        if (baseKeyManager instanceof AggregatedX509ExtendedKeyManager) {
            Map<String, X509ExtendedKeyManager> innerKeyManagers = ((AggregatedX509ExtendedKeyManager) baseKeyManager).getInnerKeyManagers();

            Optional<InflatableX509ExtendedKeyManager> inflatableKeyManager = innerKeyManagers.values().stream()
                    .filter(InflatableX509ExtendedKeyManager.class::isInstance)
                    .map(InflatableX509ExtendedKeyManager.class::cast)
                    .findFirst();

            if (inflatableKeyManager.isPresent()) {
                return computeIdentityMaterialIfPossible(inflatableKeyManager.get(), consumer);
            }
        }

        return false;
    }

    /**
     * Returns a list of aliases associated with the KeyManagers within a {@link CombinableX509KeyManager}
     */
    public static List<String> getAliases(X509ExtendedKeyManager keyManager) {
        if (keyManager instanceof InflatableX509ExtendedKeyManager) {
            return toUnmodifiableList(((InflatableX509ExtendedKeyManager) keyManager).getAliasToIdentity().keySet());
        }

        if (keyManager instanceof DelegatingX509ExtendedKeyManager) {
            return getAliases(((DelegatingX509ExtendedKeyManager) keyManager).getInnerKeyManager());
        }

        if (keyManager instanceof AggregatedX509ExtendedKeyManager) {
            Map<String, X509ExtendedKeyManager> innerKeyManagers = ((AggregatedX509ExtendedKeyManager) keyManager).getInnerKeyManagers();

            Optional<InflatableX509ExtendedKeyManager> inflatableKeyManager = innerKeyManagers.values().stream()
                    .filter(InflatableX509ExtendedKeyManager.class::isInstance)
                    .map(InflatableX509ExtendedKeyManager.class::cast)
                    .findFirst();

            if (inflatableKeyManager.isPresent()) {
                return getAliases(inflatableKeyManager.get());
            } else {
                return toUnmodifiableList(((AggregatedX509ExtendedKeyManager) keyManager).getInnerKeyManagers().keySet());
            }
        }

        return Collections.emptyList();
    }

    public static final class KeyManagerBuilder {

        private static final String EMPTY_KEY_MANAGER_EXCEPTION = "Input does not contain KeyManagers";

        private final List<X509ExtendedKeyManager> keyManagers = new ArrayList<>();
        private final Map<String, List<URI>> aliasToHost = new HashMap<>();
        private boolean swappableKeyManagerEnabled = false;
        private boolean loggingKeyManagerEnabled = false;
        private boolean inflatableKeyManagerEnabled = false;

        private KeyManagerBuilder() {}

        @SafeVarargs
        public final <T extends X509KeyManager> KeyManagerBuilder withKeyManagers(T... keyManagers) {
            for (X509KeyManager keyManager : keyManagers) {
                withKeyManager(keyManager);
            }
            return this;
        }

        public <T extends X509KeyManager> KeyManagerBuilder withKeyManagers(List<T> keyManagers) {
            for (X509KeyManager keyManager : keyManagers) {
                withKeyManager(keyManager);
            }
            return this;
        }

        public <T extends X509KeyManager> KeyManagerBuilder withKeyManager(T keyManager) {
            this.keyManagers.add(KeyManagerUtils.wrapIfNeeded(keyManager));
            return this;
        }

        public KeyManagerBuilder withIdentities(KeyStoreHolder... identities) {
            return withIdentities(Arrays.asList(identities));
        }

        public KeyManagerBuilder withIdentities(List<KeyStoreHolder> identities) {
            for (KeyStoreHolder identity : identities) {
                this.keyManagers.add(KeyManagerUtils.createKeyManager(identity.getKeyStore(), identity.getKeyPassword()));
            }
            return this;
        }

        public <T extends KeyStore> KeyManagerBuilder withIdentity(T identity, char[] identityPassword, String keyManagerAlgorithm) {
            this.keyManagers.add(KeyManagerUtils.createKeyManager(identity, identityPassword, keyManagerAlgorithm));
            return this;
        }

        public KeyManagerBuilder withSwappableKeyManager(boolean swappableKeyManagerEnabled) {
            this.swappableKeyManagerEnabled = swappableKeyManagerEnabled;
            return this;
        }

        public KeyManagerBuilder withLoggingKeyManager(boolean loggingKeyManagerEnabled) {
            this.loggingKeyManagerEnabled = loggingKeyManagerEnabled;
            return this;
        }

        public KeyManagerBuilder withInflatableKeyManager(boolean inflatableKeyManagerEnabled) {
            this.inflatableKeyManagerEnabled = inflatableKeyManagerEnabled;
            return this;
        }

        public KeyManagerBuilder withIdentityRoute(Map<String, List<URI>> aliasToHost) {
            this.aliasToHost.putAll(aliasToHost);
            return this;
        }

        public X509ExtendedKeyManager build() {
            requireNotEmpty(keyManagers, () -> new GenericKeyManagerException(EMPTY_KEY_MANAGER_EXCEPTION));

            X509ExtendedKeyManager baseKeyManager;
            if (keyManagers.size() == 1) {
                baseKeyManager = keyManagers.get(0);
            } else {
                AtomicInteger index = new AtomicInteger(0);
                baseKeyManager = keyManagers.stream()
                        .map(KeyManagerUtils::unwrapIfPossible)
                        .flatMap(Collection::stream)
                        .map(keyManager -> new SimpleImmutableEntry<>(String.valueOf(index.incrementAndGet()), keyManager))
                        .collect(toMapAndThen(extendedKeyManagers -> new AggregatedX509ExtendedKeyManager(extendedKeyManagers, aliasToHost)));
            }

            if (inflatableKeyManagerEnabled) {
                baseKeyManager = KeyManagerUtils.createInflatableKeyManager("initial-key-manager", baseKeyManager);
            }

            if (loggingKeyManagerEnabled) {
                baseKeyManager = KeyManagerUtils.createLoggingKeyManager(baseKeyManager);
            }

            if (swappableKeyManagerEnabled) {
                baseKeyManager = KeyManagerUtils.createSwappableKeyManager(baseKeyManager);
            }

            return baseKeyManager;
        }

    }

}
