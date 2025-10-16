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
package nl.altindag.ssl.sslcontext;

import nl.altindag.ssl.SSLFactory;
import nl.altindag.ssl.exception.GenericSecurityException;
import nl.altindag.ssl.provider.SSLFactoryProvider;
import nl.altindag.ssl.sslengine.FenixSSLEngine;
import nl.altindag.ssl.sslparameters.HotSwappableSSLParameters;
import nl.altindag.ssl.util.SSLParametersUtils;
import nl.altindag.ssl.util.SSLSocketUtils;
import nl.altindag.yaslf4j.Logger;
import nl.altindag.yaslf4j.LoggerFactory;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.security.SecureRandom;
import java.util.Optional;

import static java.util.Objects.nonNull;
import static nl.altindag.ssl.util.internal.ValidationUtils.GENERIC_EXCEPTION_MESSAGE;

/**
 * @author Hakan Altindag
 */
public final class FenixSSLContextSpi extends SSLContextSpi {

    private static final Logger LOGGER = LoggerFactory.getLogger(FenixSSLContextSpi.class);

    private final SSLContext sslContext;
    private final SSLParameters sslParameters;

    FenixSSLContextSpi(SSLContext sslContext, SSLParameters sslParameters) {
        this.sslContext = sslContext;
        this.sslParameters = sslParameters;
    }

    public FenixSSLContextSpi() {
        Optional<SSLFactory> sslFactory = SSLFactoryProvider.get();
        if (!sslFactory.isPresent()) {
            String message = GENERIC_EXCEPTION_MESSAGE.apply("SSLFactory");
            LOGGER.debug(message);
            throw new GenericSecurityException(message);
        }

        sslContext = sslFactory.get().getSslContext();
        sslParameters = sslFactory.get().getSslParameters();
    }

    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom sr) {
        LOGGER.debug("The provided parameters are being ignored as the SSLContext has already been initialized");
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        return SSLSocketUtils.createSslSocketFactory(sslContext, engineGetDefaultSSLParameters());
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return SSLSocketUtils.createSslServerSocketFactory(sslContext, engineGetDefaultSSLParameters());
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        return getSSLEngine(null, 0);
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port) {
        return getSSLEngine(host, port);
    }

    private SSLEngine getSSLEngine(String peerHost, int peerPort) {
        SSLEngine sslEngine;
        if (nonNull(peerHost)) {
            sslEngine = sslContext.createSSLEngine(peerHost, peerPort);
        } else {
            sslEngine = sslContext.createSSLEngine();
        }

        sslEngine.setSSLParameters(engineGetDefaultSSLParameters());
        return sslParameters instanceof HotSwappableSSLParameters ? new FenixSSLEngine(sslEngine, sslParameters) : sslEngine;
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        return sslContext.getServerSessionContext();
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        return sslContext.getClientSessionContext();
    }

    @Override
    protected SSLParameters engineGetDefaultSSLParameters() {
        return SSLParametersUtils.copy(sslParameters);
    }

    @Override
    protected SSLParameters engineGetSupportedSSLParameters() {
        return SSLParametersUtils.copy(sslContext.getSupportedSSLParameters());
    }

}
