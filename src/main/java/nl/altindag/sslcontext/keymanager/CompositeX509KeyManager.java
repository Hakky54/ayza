package nl.altindag.sslcontext.keymanager;

import java.net.Socket;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.annotation.Nullable;
import javax.net.ssl.SSLContext;
import javax.net.ssl.X509KeyManager;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;

import nl.altindag.sslcontext.model.KeyStoreHolder;
import nl.altindag.sslcontext.util.KeyManagerUtils;

/**
 * Represents an ordered list of {@link X509KeyManager X509KeyManagers} with most-preferred managers first.
 *
 * This is necessary because of the fine-print on {@link SSLContext#init}:
 *     Only the first instance of a particular key and/or trust manager implementation type in the
 *     array is used. (For example, only the first javax.net.ssl.X509KeyManager in the array will be used.)
 * The TrustManager can be build from one or more of any combination provided within the {@link Builder CompositeX509KeyManager.Builder}.
 * <br><br>
 * This includes:
 * <pre>
 *     - Any amount of custom KeyManagers
 *     - Any amount of custom Identities
 * </pre>
 *
 * @see <a href="http://stackoverflow.com/questions/1793979/registering-multiple-keystores-in-jvm">
 *     http://stackoverflow.com/questions/1793979/registering-multiple-keystores-in-jvm
 *     </a>
 * @see <a href="http://codyaray.com/2013/04/java-ssl-with-multiple-keystores">
 *     http://codyaray.com/2013/04/java-ssl-with-multiple-keystores
 *     </a>
 */
public class CompositeX509KeyManager implements X509KeyManager {

    private final List<X509KeyManager> keyManagers;

    /**
     * Creates a new {@link CompositeX509KeyManager}.
     *
     * @param keyManagers the {@link X509KeyManager X509KeyManagers}, ordered with the most-preferred managers first.
     */
    public CompositeX509KeyManager(List<? extends X509KeyManager> keyManagers) {
        this.keyManagers = ImmutableList.copyOf(keyManagers);
    }

    /**
     * Chooses the first non-null client alias returned from the delegate
     * {@link X509KeyManager X509KeyManagers}, or {@code null} if there are no matches.
     */
    @Override
    public @Nullable String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        for (X509KeyManager keyManager : keyManagers) {
            String alias = keyManager.chooseClientAlias(keyType, issuers, socket);
            if (alias != null) {
                return alias;
            }
        }
        return null;
    }

    /**
     * Chooses the first non-null server alias returned from the delegate
     * {@link X509KeyManager X509KeyManagers}, or {@code null} if there are no matches.
     */
    @Override
    public @Nullable String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        for (X509KeyManager keyManager : keyManagers) {
            String alias = keyManager.chooseServerAlias(keyType, issuers, socket);
            if (alias != null) {
                return alias;
            }
        }
        return null;
    }

    /**
     * Returns the first non-null private key associated with the
     * given alias, or {@code null} if the alias can't be found.
     */
    @Override
    public @Nullable PrivateKey getPrivateKey(String alias) {
        for (X509KeyManager keyManager : keyManagers) {
            PrivateKey privateKey = keyManager.getPrivateKey(alias);
            if (privateKey != null) {
                return privateKey;
            }
        }
        return null;
    }

    /**
     * Returns the first non-null certificate chain associated with the
     * given alias, or {@code null} if the alias can't be found.
     */
    @Override
    public @Nullable X509Certificate[] getCertificateChain(String alias) {
        for (X509KeyManager keyManager : keyManagers) {
            X509Certificate[] chain = keyManager.getCertificateChain(alias);
            if (chain != null && chain.length > 0) {
                return chain;
            }
        }
        return null;
    }

    /**
     * Get all matching aliases for authenticating the client side of a
     * secure socket, or {@code null} if there are no matches.
     */
    @Override
    public @Nullable String[] getClientAliases(String keyType, Principal[] issuers) {
        ImmutableList.Builder aliases = ImmutableList.builder();
        for (X509KeyManager keyManager : keyManagers) {
            aliases.add(keyManager.getClientAliases(keyType, issuers));
        }
        return emptyToNull(Iterables.toArray(aliases.build(), String.class));
    }

    /**
     * Get all matching aliases for authenticating the server side of a
     * secure socket, or {@code null} if there are no matches.
     */
    @Override
    public @Nullable String[] getServerAliases(String keyType, Principal[] issuers) {
        ImmutableList.Builder aliases = ImmutableList.builder();
        for (X509KeyManager keyManager : keyManagers) {
            aliases.add(keyManager.getServerAliases(keyType, issuers));
        }
        return emptyToNull(Iterables.toArray(aliases.build(), String.class));
    }

    private @Nullable <T> T[] emptyToNull(T[] arr) {
        return (arr.length == 0) ? null : arr;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private final List<X509KeyManager> keyManagers = new ArrayList<>();

        public <T extends X509KeyManager> Builder withKeyManagers(T... keyManagers) {
            return withKeyManagers(Arrays.asList(keyManagers));
        }

        public Builder withKeyManagers(List<? extends X509KeyManager> keyManagers) {
            this.keyManagers.addAll(keyManagers);
            return this;
        }

        public <T extends KeyStoreHolder> Builder withIdentities(T... identities) {
            return withIdentities(Arrays.asList(identities));
        }

        public Builder withIdentities(List<? extends KeyStoreHolder> identities) {
            for (KeyStoreHolder identity : identities) {
                this.keyManagers.add(KeyManagerUtils.createKeyManager(identity.getKeyStore(), identity.getKeyStorePassword()));
            }
            return this;
        }

        public <T extends KeyStore> Builder withIdentity(T identity, char[] identityPassword, String keyManagerAlgorithm) {
            this.keyManagers.add(KeyManagerUtils.createKeyManager(identity, identityPassword, keyManagerAlgorithm));
            return this;
        }

        public CompositeX509KeyManager build() {
            return new CompositeX509KeyManager(keyManagers);
        }

    }
}
