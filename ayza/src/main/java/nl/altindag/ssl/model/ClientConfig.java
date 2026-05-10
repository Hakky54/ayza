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
package nl.altindag.ssl.model;

import nl.altindag.laleler.ValidationUtils;
import nl.altindag.ssl.SSLFactory;

import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.time.Duration;
import java.util.Optional;

import static nl.altindag.laleler.ValidationUtils.GENERIC_EXCEPTION_MESSAGE;

public final class ClientConfig {

    private final SSLFactory sslFactory;
    private final Proxy proxy;
    private final PasswordAuthentication passwordAuthentication;
    private final Duration timeout;

    public ClientConfig(SSLFactory sslFactory, Proxy proxy, PasswordAuthentication passwordAuthentication, Duration timeout) {
        this.sslFactory = ValidationUtils.requireNotNull(sslFactory, GENERIC_EXCEPTION_MESSAGE.apply("SSLFactory"));
        this.proxy = proxy;
        this.passwordAuthentication = passwordAuthentication;
        this.timeout = timeout;
    }

    public SSLFactory getSslFactory() {
        return sslFactory;
    }

    public Optional<Proxy> getProxy() {
        return Optional.ofNullable(proxy);
    }

    public Optional<PasswordAuthentication> getPasswordAuthentication() {
        return Optional.ofNullable(passwordAuthentication);
    }

    public Optional<Duration> getTimeout() {
        return Optional.ofNullable(timeout);
    }

}
