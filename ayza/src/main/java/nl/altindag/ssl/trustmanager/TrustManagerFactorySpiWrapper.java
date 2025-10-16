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

import nl.altindag.yaslf4j.Logger;
import nl.altindag.yaslf4j.LoggerFactory;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactorySpi;
import java.security.KeyStore;

import static nl.altindag.ssl.util.internal.ValidationUtils.GENERIC_EXCEPTION_MESSAGE;
import static nl.altindag.ssl.util.internal.ValidationUtils.requireNotNull;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
class TrustManagerFactorySpiWrapper extends TrustManagerFactorySpi {

    private static final Logger LOGGER = LoggerFactory.getLogger(TrustManagerFactorySpiWrapper.class);

    private final TrustManager[] trustManagers;

    TrustManagerFactorySpiWrapper(TrustManager trustManager) {
        requireNotNull(trustManager, GENERIC_EXCEPTION_MESSAGE.apply("TrustManager"));
        this.trustManagers = new TrustManager[]{trustManager};
    }

    @Override
    protected void engineInit(KeyStore keyStore) {
        LOGGER.info("Ignoring provided KeyStore");
    }

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) {
        LOGGER.info("Ignoring provided ManagerFactoryParameters");
    }

    @Override
    protected TrustManager[] engineGetTrustManagers() {
        return trustManagers;
    }

}
