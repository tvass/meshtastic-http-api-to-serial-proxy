#!/usr/bin/env python3
"""
Meshtastic HTTP API to Local Serial Port

This proxy enables the Meshtastic web application to communicate with locally connected
Meshtastic devices by implementing the HTTP API over a direct serial connection.

Motivation:
- Chrome's Web Serial API only supports locally connected USB devices
- Direct HTTP API access for locally connected devices without WiFi

References:
- https://meshtastic.org/docs/development/device/client-api/
- https://meshtastic.org/docs/development/device/http-api/

Setup:

1. Connect your Meshtastic device via USB (e.g., /dev/ttyACM0 or /dev/ttyUSB0)

2. Run this proxy:
   $ openssl req -x509 -newkey rsa:4096 -nodes -keyout server.key -out server.crt -days 365 -subj "/CN=localhost"
   $ sudo python app-copy.py --serial-port /dev/ttyACM0 --cert server.crt --key server.key

3. Accept the self-signed certificate:
   Visit https://localhost in your browser and accept the certificate warning/exception.

4. Connect the Meshtastic web app:
   Open https://client.meshtastic.org and configure it to connect to https://localhost
"""

import asyncio
import ssl
import argparse
import logging
import os
from aiohttp import web
from collections import deque
import threading
import serial

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
        serial_port=None,
        baud_rate=115200,
    ):
        self.host = host
        self.port = port
        self.certfile = certfile
        self.keyfile = keyfile
        self.serial_port = serial_port
        self.baud_rate = baud_rate
        self.serial_conn = None
        self.ssl_context = None
        self.from_radio_queue = deque(maxlen=256)  # Buffer for messages from radio
        self.serial_lock = threading.Lock()
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

    def open_serial_port(self):
        """Open serial port connection"""
        try:
            logger.info(f"Opening serial port {self.serial_port} at {self.baud_rate} baud")
            self.serial_conn = serial.Serial(
                port=self.serial_port,
                baudrate=self.baud_rate,
                timeout=0.1
            )
            logger.info(f"Serial port {self.serial_port} opened successfully")
        except Exception as e:
            logger.error(f"Failed to open serial port: {e}")
            raise

    def close_serial_port(self):
        """Close the serial port connection"""
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.close()
            logger.info("Serial port closed")

    def serial_reader_thread(self):
        """Background thread to read from serial port and parse framed messages"""
        logger.info("Serial reader thread started")
        buffer = bytearray()

        while self.running:
            try:
                # Read from serial port
                try:
                    if self.serial_conn and self.serial_conn.is_open:
                        if self.serial_conn.in_waiting > 0:
                            with self.serial_lock:
                                data = self.serial_conn.read(self.serial_conn.in_waiting)
                                if data:
                                    logger.debug(
                                        f"Serial recv: {len(data)} bytes, hex start: {data[:50].hex()}"
                                    )
                                    buffer.extend(data)
                except serial.SerialException as e:
                    logger.error(f"Serial port error: {e}")
                    logger.info("Attempting to reconnect...")
                    try:
                        self.close_serial_port()
                        self.open_serial_port()
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

            # Write to serial port
            with self.serial_lock:
                if self.serial_conn and self.serial_conn.is_open:
                    self.serial_conn.write(framed_data)
                    logger.debug(
                        f"HTTP -> Serial: {len(protobuf_data)} bytes protobuf ({len(framed_data)} bytes framed)"
                    )
                else:
                    return web.Response(status=503, text="Serial connection not available")

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
            # Open serial port
            self.open_serial_port()

            # Start serial reader thread
            self.running = True
            serial_thread = threading.Thread(target=self.serial_reader_thread, daemon=True)
            serial_thread.start()

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
            self.close_serial_port()


async def main_async(args):
    proxy = MeshtasticHTTPProxy(
        host=args.host,
        port=args.port,
        certfile=args.cert,
        keyfile=args.key,
        serial_port=args.serial_port,
        baud_rate=args.baud_rate,
    )

    try:
        await proxy.start_server()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        proxy.running = False
        proxy.close_serial_port()


def main():
    parser = argparse.ArgumentParser(
        description="Meshtastic HTTP API to Local Serial Port Proxy"
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
        "--serial-port", required=True, help="Serial port device (e.g., /dev/ttyACM0 or /dev/ttyUSB0)"
    )
    parser.add_argument(
        "--baud-rate", type=int, default=115200, help="Serial baud rate (default: 115200)"
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
