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
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static nl.altindag.laleler.ValidationUtils.GENERIC_EXCEPTION_MESSAGE;
import static nl.altindag.laleler.ValidationUtils.requireNotNull;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
abstract class DelegatingTrustManager<T extends X509TrustManager> extends X509ExtendedTrustManager {

    T trustManager;

    DelegatingTrustManager(T trustManager) {
        this.trustManager = requireNotNull(trustManager, GENERIC_EXCEPTION_MESSAGE.apply("TrustManager"));
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        trustManager.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        trustManager.checkServerTrusted(chain, authType);
    }

    @Override
    public abstract void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException;

    @Override
    public abstract void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException;

    @Override
    public abstract void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException;

    @Override
    public abstract void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException;

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        X509Certificate[] acceptedIssuers = trustManager.getAcceptedIssuers();
        return Arrays.copyOf(acceptedIssuers, acceptedIssuers.length);
    }

    public T getInnerTrustManager() {
        return trustManager;
    }

}
