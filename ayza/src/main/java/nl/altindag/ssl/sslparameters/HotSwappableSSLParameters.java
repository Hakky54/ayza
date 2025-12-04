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
package nl.altindag.ssl.sslparameters;

import javax.net.ssl.SSLParameters;
import java.security.AlgorithmConstraints;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Supplier;

import static nl.altindag.ssl.util.internal.ValidationUtils.GENERIC_EXCEPTION_MESSAGE;
import static nl.altindag.ssl.util.internal.ValidationUtils.requireNotNull;

public final class HotSwappableSSLParameters extends DelegatingSSLParameters {

    private final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
    private final Lock readLock = readWriteLock.readLock();
    private final Lock writeLock = readWriteLock.writeLock();

    public HotSwappableSSLParameters(SSLParameters sslParameters) {
        super(sslParameters);
    }

    @Override
    public void setSslParameters(SSLParameters sslParameters) {
        setSafely(() -> super.setSslParameters(requireNotNull(sslParameters, GENERIC_EXCEPTION_MESSAGE.apply("SSLParameters"))));
    }

    @Override
    public SSLParameters getInnerSslParameters() {
        return getSafely(super::getInnerSslParameters);
    }

    @Override
    public String[] getCipherSuites() {
        return getSafely(super::getCipherSuites);
    }

    @Override
    public String[] getProtocols() {
        return getSafely(super::getProtocols);
    }

    @Override
    public boolean getWantClientAuth() {
        return getSafely(super::getWantClientAuth);
    }

    @Override
    public boolean getNeedClientAuth() {
        return getSafely(super::getNeedClientAuth);
    }

    @Override
    public AlgorithmConstraints getAlgorithmConstraints() {
        return getSafely(super::getAlgorithmConstraints);
    }

    @Override
    public String getEndpointIdentificationAlgorithm() {
        return getSafely(super::getEndpointIdentificationAlgorithm);
    }

    @Override
    public void setCipherSuites(String[] cipherSuites) {
        setSafely(() -> super.setCipherSuites(cipherSuites));
    }

    @Override
    public void setProtocols(String[] protocols) {
        setSafely(() -> super.setProtocols(protocols));
    }

    @Override
    public void setWantClientAuth(boolean wantClientAuth) {
        setSafely(() -> super.setWantClientAuth(wantClientAuth));
    }

    @Override
    public void setNeedClientAuth(boolean needClientAuth) {
        setSafely(() -> super.setNeedClientAuth(needClientAuth));
    }

    @Override
    public void setAlgorithmConstraints(AlgorithmConstraints constraints) {
        setSafely(() -> super.setAlgorithmConstraints(constraints));
    }

    @Override
    public void setEndpointIdentificationAlgorithm(String algorithm) {
        setSafely(() -> super.setEndpointIdentificationAlgorithm(algorithm));
    }

    private <V> V getSafely(Supplier<V> supplier) {
        readLock.lock();
        try {
            return supplier.get();
        } finally {
            readLock.unlock();
        }
    }

    private void setSafely(SSLParametersRunnable sslParametersRunnable) {
        writeLock.lock();

        try {
            sslParametersRunnable.run();
        } finally {
            writeLock.unlock();
        }
    }

}
