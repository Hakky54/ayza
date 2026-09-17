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

import nl.altindag.log.LogCaptor;
import nl.altindag.ssl.exception.GenericSecurityException;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * @author Hakan Altindag
 */
class FenixSSLContextSpiShould {

    @Test
    void ignoreProvidedParametersAndDebugLogWhenEngineInitIsBeingCalled() {
        LogCaptor logCaptor = LogCaptor.forClass(FenixSSLContextSpi.class);

        FenixSSLContextSpi sslContextSpi = new FenixSSLContextSpi(null, null, null);
        sslContextSpi.engineInit(null, null, null);

        assertThat(logCaptor.getDebugLogs())
                .containsExactly("The provided parameters are being ignored as the SSLContext has already been initialized");
    }

    @Test
    void throwExceptionAndDebugLogWhenDefaultConstructorIsCalledWhileSslFactoryProviderIsNotInitialized() {
        LogCaptor logCaptor = LogCaptor.forClass(FenixSSLContextSpi.class);
        String expectedMessage = "No valid SSLFactory has been provided. SSLFactory must be present, but was absent.";

        assertThatThrownBy(FenixSSLContextSpi::new)
                .isInstanceOf(GenericSecurityException.class)
                .hasMessage(expectedMessage);

        List<String> logs = logCaptor.getDebugLogs();
        assertThat(logs).contains(expectedMessage);
    }

}
