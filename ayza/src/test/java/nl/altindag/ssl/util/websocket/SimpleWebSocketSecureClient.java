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
package nl.altindag.ssl.util.websocket;

import nl.altindag.yaslf4j.Logger;
import nl.altindag.yaslf4j.LoggerFactory;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import java.net.URI;

public class SimpleWebSocketSecureClient extends WebSocketClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(SimpleWebSocketSecureClient.class);

    public SimpleWebSocketSecureClient(URI serverUri) {
        super(serverUri);
    }

    @Override
    public void onOpen(ServerHandshake handshake) {
        LOGGER.debug("Connected");
    }

    @Override
    public void onMessage(String message) {
        LOGGER.debug(String.format("got: %s", message));
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        LOGGER.debug("Disconnected");
    }

    @Override
    public void onError(Exception ex) {
        LOGGER.error("Error", ex);
    }

}

