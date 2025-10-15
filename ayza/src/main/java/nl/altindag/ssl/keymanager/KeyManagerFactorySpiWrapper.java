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

import nl.altindag.yaslf4j.Logger;
import nl.altindag.yaslf4j.LoggerFactory;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import java.security.KeyStore;

import static nl.altindag.ssl.util.internal.ValidationUtils.requireNotNull;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
class KeyManagerFactorySpiWrapper extends KeyManagerFactorySpi {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyManagerFactorySpiWrapper.class);
    private static final String NO_KEY_MANAGER_EXCEPTION_MESSAGE = "No valid KeyManager has been provided. KeyManager must be present, but was absent.";

    private final KeyManager[] keyManagers;

    KeyManagerFactorySpiWrapper(KeyManager keyManager) {
        requireNotNull(keyManager, NO_KEY_MANAGER_EXCEPTION_MESSAGE);
        this.keyManagers = new KeyManager[]{keyManager};
    }

    @Override
    protected void engineInit(KeyStore keyStore, char[] keyStorePassword) {
        LOGGER.info("Ignoring provided KeyStore");
    }

    @Override
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) {
        LOGGER.info("Ignoring provided ManagerFactoryParameters");
    }

    @Override
    protected KeyManager[] engineGetKeyManagers() {
        return keyManagers;
    }

}
