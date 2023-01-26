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
package nl.altindag.ssl.util;

import java.net.URI;
import java.net.URISyntaxException;

import static java.util.Objects.isNull;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public final class UriUtils {

    private UriUtils() {}

    public static void validate(URI uri) {
        if (isNull(uri)) {
            throw new IllegalArgumentException("Host should be present");
        }

        if (isNull(uri.getHost())) {
            throw new IllegalArgumentException(String.format("Hostname should be defined for the given input: [%s]", uri));
        }

        if (uri.getPort() == -1) {
            throw new IllegalArgumentException(String.format("Port should be defined for the given input: [%s]", uri));
        }
    }

    public static String extractHost(String value) {
        try {
            URI url = new URI(value);
            return url.getHost();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
    }

}
