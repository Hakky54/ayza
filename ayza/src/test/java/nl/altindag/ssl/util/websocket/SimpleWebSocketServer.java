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

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

import nl.altindag.yaslf4j.Logger;
import nl.altindag.yaslf4j.LoggerFactory;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;

public class SimpleWebSocketServer extends WebSocketServer {

    private static final Logger LOGGER = LoggerFactory.getLogger(SimpleWebSocketServer.class);

    public SimpleWebSocketServer(InetSocketAddress address) {
        super(address);
    }

    @Override
    public void onOpen(WebSocket conn, ClientHandshake handshake) {
        conn.send("Welcome to the server!"); //This method sends a message to the new client
        broadcast( "new connection: " + handshake.getResourceDescriptor() ); //This method sends a message to all clients connected
        LOGGER.debug(String.format("new connection to %s", conn.getRemoteSocketAddress()));
    }

    @Override
    public void onClose(WebSocket conn, int code, String reason, boolean remote) {
        LOGGER.debug(String.format("closed %s with exit code %s additional info: %s", conn.getRemoteSocketAddress(), code, reason));
    }

    @Override
    public void onMessage(WebSocket conn, String message) {
        LOGGER.debug(String.format("received message from %s: %s", conn.getRemoteSocketAddress(), message));
    }

    @Override
    public void onMessage( WebSocket conn, ByteBuffer message ) {
        LOGGER.debug(String.format("received ByteBuffer from %s", conn.getRemoteSocketAddress()));
    }

    @Override
    public void onError(WebSocket conn, Exception ex) {
        LOGGER.error(String.format("an error occurred on connection %s", conn.getRemoteSocketAddress()));
    }

    @Override
    public void onStart() {
        LOGGER.debug("server started successfully");
    }

}