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

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
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
 * Instead use the {@link nl.altindag.ssl.util.TrustManagerUtils TrustManagerUtils} which provides the same functionality
 * while it has a stable API because it is part of the public API.
 *
 * @author Hakan Altindag
 */
public class HotSwappableX509ExtendedTrustManager extends DelegatingX509ExtendedTrustManager {

    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    protected final Lock readLock = readWriteLock.readLock();
    protected final Lock writeLock = readWriteLock.writeLock();

    public HotSwappableX509ExtendedTrustManager(X509ExtendedTrustManager trustManager) {
        super(trustManager);
    }

    public void setTrustManager(X509ExtendedTrustManager trustManager) {
        writeLock.lock();

        try {
            this.trustManager = requireNotNull(trustManager, GENERIC_EXCEPTION_MESSAGE.apply("TrustManager"));
        } finally {
            writeLock.unlock();
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(() -> super.checkServerTrusted(chain, authType));
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkTrusted(() -> super.checkServerTrusted(chain, authType, socket));
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        checkTrusted(() -> super.checkServerTrusted(chain, authType, sslEngine));
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(() -> super.checkClientTrusted(chain, authType));
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkTrusted(() -> super.checkClientTrusted(chain, authType, socket));
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine sslEngine) throws CertificateException {
        checkTrusted(() -> super.checkClientTrusted(chain, authType, sslEngine));
    }

    private void checkTrusted(TrustManagerRunnable trustManagerRunnable) throws CertificateException {
        readLock.lock();
        try {
            trustManagerRunnable.run();
        } finally {
            readLock.unlock();
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return getObjectSafely(super::getAcceptedIssuers);
    }

    @Override
    public X509ExtendedTrustManager getInnerTrustManager() {
        return getObjectSafely(super::getInnerTrustManager);
    }

    private <T> T getObjectSafely(Supplier<T> supplier) {
        readLock.lock();
        try {
            return supplier.get();
        } finally {
            readLock.unlock();
        }
    }
}
