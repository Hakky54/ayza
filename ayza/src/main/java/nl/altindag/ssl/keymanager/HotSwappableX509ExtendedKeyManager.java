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
package nl.altindag.ssl.keymanager;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Supplier;

import static nl.altindag.laleler.ValidationUtils.GENERIC_EXCEPTION_MESSAGE;
import static nl.altindag.laleler.ValidationUtils.requireNotNull;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 * Instead use the {@link nl.altindag.ssl.util.KeyManagerUtils KeyManagerUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 *
 * @author Hakan Altindag
 */
public class HotSwappableX509ExtendedKeyManager extends DelegatingX509ExtendedKeyManager {

    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    protected final Lock readLock = readWriteLock.readLock();
    protected final Lock writeLock = readWriteLock.writeLock();

    public HotSwappableX509ExtendedKeyManager(X509ExtendedKeyManager keyManager) {
        super(keyManager);
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return getObjectSafely(() -> super.chooseClientAlias(keyType, issuers, socket));
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return getObjectSafely(() -> super.chooseServerAlias(keyType, issuers, socket));
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return getObjectSafely(() -> super.getPrivateKey(alias));
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return getObjectSafely(() -> super.getCertificateChain(alias));
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return getObjectSafely(() -> super.getClientAliases(keyType, issuers));
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return getObjectSafely(() -> super.getServerAliases(keyType, issuers));
    }

    @Override
    public X509ExtendedKeyManager getInnerKeyManager() {
        return getObjectSafely(super::getInnerKeyManager);
    }

    @Override
    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine sslEngine) {
        return getObjectSafely(() -> super.chooseEngineClientAlias(keyTypes, issuers, sslEngine));
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine sslEngine) {
        return getObjectSafely(() -> super.chooseEngineServerAlias(keyType, issuers, sslEngine));
    }

    private <T> T getObjectSafely(Supplier<T> supplier) {
        readLock.lock();

        try {
            return supplier.get();
        } finally {
            readLock.unlock();
        }
    }

    public void setKeyManager(X509ExtendedKeyManager keyManager) {
        writeLock.lock();

        try {
            this.keyManager = requireNotNull(keyManager, GENERIC_EXCEPTION_MESSAGE.apply("KeyManager"));
        } finally {
            writeLock.unlock();
        }
    }

}
