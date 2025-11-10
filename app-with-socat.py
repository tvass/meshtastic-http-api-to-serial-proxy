#!/usr/bin/env python3
"""
Meshtastic HTTP API to Serial exposed in TCP via socat

This proxy enables the Meshtastic web application to communicate with devices that lack WiFi
capabilities (like the RAK4631) by bridging HTTPS/HTTP to a remote serial connection via socat.

Motivation:
- Chrome's Web Serial API only supports locally connected USB devices
- WiFi-less Meshtastic devices need an alternative way to connect to the web application

References:
- https://meshtastic.org/docs/development/device/client-api/
- https://meshtastic.org/docs/development/device/http-api/

Setup:

1. On the Linux host with the Meshtastic device (Raspberry Pi, etc.):
   $ sudo socat -d -d TCP-LISTEN:4403,reuseaddr,fork FILE:/dev/ttyACM0,raw,echo=0,b115200

2. On your local machine, run this proxy:
   $ openssl req -x509 -newkey rsa:4096 -nodes -keyout server.key -out server.crt -days 365 -subj "/CN=localhost"
   $ sudo python app.py --tcp-host 192.168.0.164 --tcp-port 4403 --cert server.crt --key server.key

3. Accept the self-signed certificate:
   Visit https://localhost:8080 in your browser and accept the certificate warning/exception.

4. Connect the Meshtastic web app:
   Open https://client.meshtastic.org and configure it to connect to https://localhost:8080
"""

import asyncio
import ssl
import socket as sock
import argparse
import logging
import os
from aiohttp import web
from collections import deque
import threading

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class MeshtasticHTTPProxy:
    def __init__(
        self,
        host="0.0.0.0",
        port=443,
        certfile=None,
        keyfile=None,
        tcp_host=None,
        tcp_port=None,
    ):
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port
        self.tcp_socket = None
        self.ssl_context = None
        self.from_radio_queue = deque(maxlen=256)  # Buffer for messages from radio
        self.socket_lock = threading.Lock()
        self.running = False

        # Auto-detect TLS based on certificate presence
        self.use_tls = bool(self.certfile and self.keyfile)

        # Setup SSL context if certificates are provided
        if self.use_tls:
            self._setup_ssl()

    def _setup_ssl(self):
        """Setup SSL context for TLS connections"""
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        if not os.path.exists(self.certfile):
            raise FileNotFoundError(f"Certificate file not found: {self.certfile}")

        if not os.path.exists(self.keyfile):
            raise FileNotFoundError(f"Key file not found: {self.keyfile}")

        self.ssl_context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        logger.info(f"SSL/TLS enabled with certificate: {self.certfile}")

    def open_tcp_connection(self):
        """Open TCP connection to socat"""
        try:
            logger.info(f"Connecting to TCP socket {self.tcp_host}:{self.tcp_port}")
            self.tcp_socket = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
            self.tcp_socket.connect((self.tcp_host, self.tcp_port))
            self.tcp_socket.settimeout(0.1)
            logger.info(f"Connected to TCP socket {self.tcp_host}:{self.tcp_port}")
        except Exception as e:
            logger.error(f"Failed to open TCP connection: {e}")
            raise

    def close_tcp_connection(self):
        """Close the TCP connection"""
        if self.tcp_socket:
            self.tcp_socket.close()
            logger.info("TCP socket closed")

    def tcp_reader_thread(self):
        """Background thread to read from TCP socket and parse framed messages"""
        logger.info("TCP reader thread started")
        buffer = bytearray()

        while self.running:
            try:
                # Read from TCP socket
                try:
                    with self.socket_lock:
                        data = self.tcp_socket.recv(4096)
                        if data:
                            logger.debug(
                                f"TCP recv: {len(data)} bytes, hex start: {data[:50].hex()}"
                            )
                            buffer.extend(data)
                except sock.timeout:
                    pass  # No data available
                except Exception as e:
                    logger.error(f"TCP socket error: {e}")
                    logger.info("Attempting to reconnect...")
                    try:
                        self.close_tcp_connection()
                        self.open_tcp_connection()
                    except Exception as reconnect_error:
                        logger.error(f"Reconnection failed: {reconnect_error}")
                        break

                # Parse framed messages from buffer
                while len(buffer) >= 4:
                    # Look for frame header: 0x94 0xc3
                    if buffer[0] == 0x94 and buffer[1] == 0xC3:
                        # Get message length (big-endian)
                        msg_len = (buffer[2] << 8) | buffer[3]

                        # Validate length
                        if msg_len > 512 or msg_len == 0:
                            logger.warning(
                                f"Invalid message length {msg_len}, resynchronizing. Buffer start: {buffer[:16].hex()}"
                            )
                            buffer.pop(0)
                            continue

                        # Check if we have the complete message
                        if len(buffer) >= 4 + msg_len:
                            # Extract the protobuf message (without frame header)
                            protobuf_data = bytes(buffer[4 : 4 + msg_len])

                            self.from_radio_queue.append(protobuf_data)
                            logger.debug(
                                f"Serial -> Queue: {len(protobuf_data)} bytes (queue: {len(self.from_radio_queue)}), hex: {protobuf_data[:20].hex()}"
                            )

                            # Remove processed message from buffer
                            buffer = buffer[4 + msg_len :]
                        else:
                            # Wait for more data
                            break
                    else:
                        # Not a valid frame start, skip byte and resynchronize
                        buffer.pop(0)

            except Exception as e:
                logger.error(f"Error in serial reader: {e}")

            threading.Event().wait(0.01)  # Small delay

    async def handle_toradio(self, request):
        """Handle PUT requests to /api/v1/toradio"""
        if request.method == "OPTIONS":
            # CORS preflight
            return web.Response(
                status=204,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "PUT, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type",
                },
            )

        try:
            # Read the protobuf data from request body
            protobuf_data = await request.read()

            if not protobuf_data:
                return web.Response(status=400, text="Empty request body")

            # Add frame header: 0x94 0xc3 [length_msb] [length_lsb]
            msg_len = len(protobuf_data)
            if msg_len > 512:
                return web.Response(status=400, text="Message too large")

            length_msb = (msg_len >> 8) & 0xFF
            length_lsb = msg_len & 0xFF
            framed_data = bytes([0x94, 0xC3, length_msb, length_lsb]) + protobuf_data

            # Write to TCP socket
            with self.socket_lock:
                if self.tcp_socket:
                    self.tcp_socket.sendall(framed_data)
                    logger.debug(
                        f"HTTP -> TCP: {len(protobuf_data)} bytes protobuf ({len(framed_data)} bytes framed)"
                    )
                else:
                    return web.Response(status=503, text="TCP connection not available")

            return web.Response(
                status=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Content-Type": "application/x-protobuf",
                },
            )

        except Exception as e:
            logger.error(f"Error in toradio handler: {e}")
            return web.Response(status=500, text=str(e))

    async def handle_fromradio(self, request):
        """Handle GET requests to /api/v1/fromradio"""
        try:
            # Check if 'all' parameter is present
            all_messages = request.query.get("all", "").lower() in ("true", "1", "yes")

            if all_messages:
                # Return all available messages
                messages = []
                while self.from_radio_queue:
                    messages.append(self.from_radio_queue.popleft())

                if messages:
                    # Concatenate all messages
                    data = b"".join(messages)
                    logger.debug(
                        f"Serial -> HTTP: {len(data)} bytes (all, {len(messages)} messages)"
                    )
                else:
                    data = b""
                    logger.debug(f"Serial -> HTTP: empty (all=true, no messages)")
            else:
                # Return one message
                if self.from_radio_queue:
                    data = self.from_radio_queue.popleft()
                    logger.debug(
                        f"Serial -> HTTP: {len(data)} bytes (queue size: {len(self.from_radio_queue)})"
                    )
                else:
                    data = b""
                    # Don't log every empty poll to reduce spam
                    # logger.debug(f"Serial -> HTTP: empty (no messages)")

            return web.Response(
                body=data,
                status=200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Content-Type": "application/x-protobuf",
                    "X-Protobuf-Schema": "https://buf.build/meshtastic/protobufs",
                },
            )

        except Exception as e:
            logger.error(f"Error in fromradio handler: {e}")
            return web.Response(status=500, text=str(e))

    async def handle_cors_preflight(self, request):
        """Handle CORS preflight requests"""
        return web.Response(
            status=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, PUT, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type",
            },
        )

    async def start_server(self):
        """Start the HTTP server"""
        try:
            # Open TCP connection
            self.open_tcp_connection()

            # Start TCP reader thread
            self.running = True
            tcp_thread = threading.Thread(target=self.tcp_reader_thread, daemon=True)
            tcp_thread.start()

            # Give the reader thread a moment to stabilize
            await asyncio.sleep(0.5)

            # Create aiohttp application
            app = web.Application()

            # Add routes
            app.router.add_route("PUT", "/api/v1/toradio", self.handle_toradio)
            app.router.add_route("OPTIONS", "/api/v1/toradio", self.handle_toradio)
            app.router.add_route("GET", "/api/v1/fromradio", self.handle_fromradio)
            app.router.add_route(
                "OPTIONS", "/api/v1/fromradio", self.handle_cors_preflight
            )

            # Start web server
            protocol = "https" if self.use_tls else "http"
            logger.info(
                f"Starting Meshtastic HTTP API server on {protocol}://{self.host}:{self.port}"
            )

            runner = web.AppRunner(app)
            await runner.setup()

            site = web.TCPSite(
                runner, self.host, self.port, ssl_context=self.ssl_context
            )

            await site.start()
            logger.info(f"Server listening on {protocol}://{self.host}:{self.port}")
            logger.info(
                f"Endpoints: {protocol}://{self.host}:{self.port}/api/v1/toradio"
            )
            logger.info(
                f"           {protocol}://{self.host}:{self.port}/api/v1/fromradio"
            )

            # Keep running
            while self.running:
                await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"Error starting server: {e}")
            raise
        finally:
            self.running = False
            self.close_tcp_connection()


async def main_async(args):
    proxy = MeshtasticHTTPProxy(
        host=args.host,
        port=args.port,
        certfile=args.cert,
        keyfile=args.key,
        tcp_host=args.tcp_host,
        tcp_port=args.tcp_port,
    )

    try:
        await proxy.start_server()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        proxy.running = False
        proxy.close_tcp_connection()


def main():
    parser = argparse.ArgumentParser(
        description="Meshtastic HTTP API to TCP Proxy (via socat)"
    )
    parser.add_argument(
        "--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Port to listen on (default: 443 for HTTPS, 8080 for HTTP)",
    )
    parser.add_argument(
        "--tcp-host", required=True, help="Remote TCP host (socat server)"
    )
    parser.add_argument(
        "--tcp-port", type=int, required=True, help="Remote TCP port (socat server)"
    )
    parser.add_argument(
        "--cert",
        help="Path to TLS certificate file (enables HTTPS if provided with --key)",
    )
    parser.add_argument(
        "--key",
        help="Path to TLS private key file (enables HTTPS if provided with --cert)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    # Validate certificate arguments
    if (args.cert and not args.key) or (args.key and not args.cert):
        parser.error("Both --cert and --key must be provided together for HTTPS")

    # Auto-set default port based on TLS presence
    if args.port is None:
        args.port = 443 if (args.cert and args.key) else 8080
        logger.info(
            f"Auto-selected port {args.port} ({'HTTPS' if args.cert else 'HTTP'} mode)"
        )

    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        logger.info("Shutting down...")


if __name__ == "__main__":
    main()
