# dnsServerMicropython.py
# Adapted for MicroPython with camelCase naming and DNS relay functionality

try:
    import usocket as socket
except ImportError:
    import socket # Fallback
import struct
import dnsUtilsMicropython as dnsUtils # Use the MicroPython version with camelCase
try:
    import urandom as random
except ImportError:
    import random
import time

# --- Configuration ---
SERVER_HOST = '0.0.0.0' # Listen on all available interfaces
SERVER_PORT = 53530     # Use a non-privileged port (standard DNS is 53)
MAX_UDP_PAYLOAD_SIZE = 512
UPSTREAM_DNS_SERVER_IP = '8.8.8.8' # Google's Public DNS
UPSTREAM_DNS_SERVER_PORT = 53
UPSTREAM_TIMEOUT_SECONDS = 2 # Timeout for querying the upstream server

# Simple Zone Data (Hostname -> IP Address)
# Domain names should end with a dot to signify FQDN.
zoneData = {
    "example.com.": "192.0.2.1",
    "www.example.com.": "192.0.2.2",
    "test.example.com.": "192.0.2.3",
    "another.domain.": "10.0.0.1",
    # Add a record for the ESP8266 itself if you want it to resolve its own name
    # "myesp.local.": "YOUR_ESP_IP_ADDRESS_HERE", # Replace with actual IP
}
# --- End Configuration ---

def forwardDnsQuery(originalQueryPacket, originalQueryId, upstreamServerIp, upstreamServerPort):
    """
    Forwards a DNS query to an upstream server and returns the response packet.
    """
    forwardSock = None
    try:
        # Create a new socket for forwarding
        addrInfo = socket.getaddrinfo(upstreamServerIp, upstreamServerPort, socket.AF_INET, socket.SOCK_DGRAM)
        upstreamAddr = addrInfo[0][-1]

        forwardSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        forwardSock.settimeout(UPSTREAM_TIMEOUT_SECONDS)

        print(f"[Server] Forwarding query ID {originalQueryId} to {upstreamServerIp}:{upstreamServerPort}")
        forwardSock.sendto(originalQueryPacket, upstreamAddr)

        # Wait for the response from the upstream server
        responsePacket, _ = forwardSock.recvfrom(MAX_UDP_PAYLOAD_SIZE)
        print(f"[Server] Received forwarded response (len: {len(responsePacket)})")
        return responsePacket # This is the full DNS packet from upstream

    except socket.timeout:
        print(f"[Server] Upstream DNS server {upstreamServerIp} timed out.")
        return None
    except OSError as e:
        print(f"[Server] OSError during forwarding to {upstreamServerIp}: {e}")
        return None
    except Exception as e:
        print(f"[Server] Unexpected error during forwarding: {e}")
        return None
    finally:
        if forwardSock:
            forwardSock.close()

def handleDnsQuery(data, clientAddress, sock):
    """
    Handles a single DNS query.
    Parses the query, looks up the name locally, or forwards if not found.
    Builds a response and sends it.
    """
    try:
        # 1. Parse the incoming request
        header = dnsUtils.parseDnsHeader(data)
        print(f"[Server] Query ID {header['id']} from {clientAddress}")

        if header['qdCount'] != 1:
            print(f"[Server] QDCOUNT {header['qdCount']} not supported. Ignoring.")
            return

        # Extract the original question section for potential forwarding
        # The question starts after the 12-byte header.
        # We need to find the end of the question to know its full length.
        qName, qType, qClass, questionEndOffset = dnsUtils.parseDnsQuestion(data, 12)
        originalQuestionBytes = data[12:questionEndOffset]
        
        print(f"[Server] Q: '{qName}' T={qType} C={qClass}")

        # 2. Prepare for response (defaults)
        responseHeaderQr = 1  # Response
        responseHeaderAa = 0  # Assume not authoritative if forwarding, authoritative if local
        responseHeaderTc = 0  # Not truncated
        responseHeaderRa = 0  # Recursion Available (will be set if we successfully forward)
        responseHeaderRd = header['rd'] # Echo RD flag from query
        
        responseAnCount = 0
        responseNsCount = 0 # Not providing NS records in this simple server
        responseArCount = 0 # Not providing Additional records
        responseRcode = 0 # No error by default
        answerRrsBytes = b""

        # 3. Look up QNAME in local zoneData or forward
        # We primarily handle A record queries locally. Others could be forwarded.
        if qType == dnsUtils.TYPE_A and qClass == dnsUtils.CLASS_IN and qName in zoneData:
            # Found in local zone
            responseHeaderAa = 1 # We are authoritative for this
            responseHeaderRa = 0 # No recursion performed for local resolution
            ipAddressStr = zoneData[qName]
            try:
                rdata = dnsUtils.packIpv4Address(ipAddressStr)
            except ValueError as e:
                print(f"[Server] Error packing IP {ipAddressStr} for local zone: {e}")
                responseRcode = 2 # Server failure
            else:
                ttl = 3600 # 1 hour
                namePointer = struct.pack("!H", 0xC00C) # Pointer to QNAME at offset 12

                answerRr = dnsUtils.buildDnsRr(
                    nameEncodedOrPointer=namePointer,
                    rType=dnsUtils.TYPE_A,
                    rClass=dnsUtils.CLASS_IN,
                    ttl=ttl,
                    rData=rdata
                )
                answerRrsBytes += answerRr
                responseAnCount = 1
                print(f"[Server] Local: Found '{qName}' -> {ipAddressStr}")
            
            # Build and send local response
            responseHeaderBytes = dnsUtils.buildDnsHeader(
                tid=header['id'], qr=responseHeaderQr, opcode=header['opcode'],
                aa=responseHeaderAa, tc=responseHeaderTc, rd=responseHeaderRd,
                ra=responseHeaderRa, rcode=responseRcode,
                qdCount=header['qdCount'], anCount=responseAnCount,
                nsCount=responseNsCount, arCount=responseArCount
            )
            responsePacket = responseHeaderBytes + originalQuestionBytes + answerRrsBytes
            sock.sendto(responsePacket, clientAddress)
            print(f"[Server] Sent local response to {clientAddress}")

        else:
            # Not in local zone or not an A record we handle locally: Try forwarding
            print(f"[Server] Local: '{qName}' not in zone or type {qType} not handled locally. Attempting forward...")
            
            # The data (original query packet) can be forwarded as is.
            # The upstream server will respond to our ESP8266.
            forwardedResponsePacket = forwardDnsQuery(data, header['id'], UPSTREAM_DNS_SERVER_IP, UPSTREAM_DNS_SERVER_PORT)

            if forwardedResponsePacket:
                # If we got a response from upstream, send it back to the client.
                # The TID in forwardedResponsePacket should match the original client's TID
                # because we forwarded the original packet.
                # We should set RA (Recursion Available) flag if we successfully got a response.
                # The upstream server's response likely has RA set if it performed recursion.
                # For simplicity, we can parse the forwarded response header to check its RA,
                # or just set RA=1 in our "outer" header if we are acting as a forwarder.

                # Let's try to send the exact packet from upstream if its TID matches.
                # The source IP will be our server, which is correct.
                # We might need to adjust our server's own header flags (like RA).
                # A simpler approach for now: send the raw forwarded packet.
                # The client will see the response as coming from our server.
                
                # Optional: Modify the RA flag in the forwarded packet if needed,
                # but this requires parsing and rebuilding, which adds complexity.
                # For now, send as is.
                sock.sendto(forwardedResponsePacket, clientAddress)
                print(f"[Server] Sent forwarded response to {clientAddress}")
            else:
                # Forwarding failed (e.g., timeout or other error)
                # Send a SERVFAIL (RCODE 2) to the original client
                responseRcode = 2 # Server Failure
                responseHeaderAa = 0 # Not authoritative for this error
                responseHeaderRa = 0 # Recursion was attempted but failed

                responseHeaderBytes = dnsUtils.buildDnsHeader(
                    tid=header['id'], qr=responseHeaderQr, opcode=header['opcode'],
                    aa=responseHeaderAa, tc=responseHeaderTc, rd=responseHeaderRd,
                    ra=responseHeaderRa, rcode=responseRcode,
                    qdCount=header['qdCount'], anCount=0, # No answers on failure
                    nsCount=0, arCount=0
                )
                errorResponsePacket = responseHeaderBytes + originalQuestionBytes # No answer section
                sock.sendto(errorResponsePacket, clientAddress)
                print(f"[Server] Sent SERVFAIL to {clientAddress} after forwarding failure.")

    except ValueError as e:
        print(f"[Server] Value error processing packet: {e}")
    except Exception as e:
        print(f"[Server] Unexpected error in handleDnsQuery: {e}")


def runDnsServer():
    """Starts the DNS server and listens for incoming queries."""
    # Network connection should be established before calling this.
    # Example: Ensure sta_if.isconnected() is true.
    # import network
    # sta_if = network.WLAN(network.STA_IF)
    # print(f"[Server] ESP8266 IP: {sta_if.ifconfig()[0]}")

    try:
        addrInfo = socket.getaddrinfo(SERVER_HOST, SERVER_PORT, 0, socket.SOCK_DGRAM)
        addr = addrInfo[0][-1]
    except OSError as e:
        print(f"[Server] Error getting address info for {SERVER_HOST}:{SERVER_PORT}: {e}")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except OSError as e:
        print(f"[Server] Warning: Could not set SO_REUSEADDR: {e}")

    try:
        sock.bind(addr)
        print(f"[Server] DNS Server listening on {SERVER_HOST}:{SERVER_PORT} (resolved to {addr})")
        print(f"[Server] Zone Data: {zoneData}")
        print(f"[Server] Upstream DNS: {UPSTREAM_DNS_SERVER_IP}:{UPSTREAM_DNS_SERVER_PORT}")
    except OSError as e:
        print(f"[Server] Error binding to {addr}: {e}")
        sock.close()
        return

    print("[Server] Waiting for queries...")
    while True:
        try:
            data, clientAddress = sock.recvfrom(MAX_UDP_PAYLOAD_SIZE)
            handleDnsQuery(data, clientAddress, sock)
        except OSError as e:
            print(f"[Server] OSError in main loop: {e}")
            time.sleep_ms(100) # Avoid rapid looping on some errors
        except Exception as e:
            print(f"[Server] Error in server loop: {e}")
            time.sleep_ms(100)

if __name__ == "__main__":
    # Add your WiFi connection logic here first if needed
    # import networkSetup # Your hypothetical module for WiFi
    # if networkSetup.connectWifi("YourSSID", "YourPassword"):
    #     runDnsServer()
    # else:
    #     print("Failed to connect to WiFi. Server not started.")
    
    print("Starting DNS server (ensure WiFi is connected)...")
    runDnsServer()
