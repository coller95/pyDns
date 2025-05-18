# dnsClientMicropython.py
# Adapted for MicroPython with camelCase naming

try:
    import usocket as socket
except ImportError:
    import socket # Fallback
import struct
try:
    import urandom as random # MicroPython uses urandom
except ImportError:
    import random

import dnsUtilsMicropython as dnsUtils # Use the MicroPython version with camelCase

# --- Configuration ---
DEFAULT_DNS_SERVER_IP = '127.0.0.1' # Change if server is on another machine
DEFAULT_DNS_SERVER_PORT = 53530     # Must match the server's port
CLIENT_TIMEOUT_SECONDS = 5
# --- End Configuration ---

def sendDnsQuery(domainName, serverIp, serverPort, qType=dnsUtils.TYPE_A):
    """
    Sends a DNS query to the specified server and returns the parsed response.
    """
    sock = None # Initialize sock to None for finally block
    try:
        # 1. Get address info for the server
        try:
            addrInfo = socket.getaddrinfo(serverIp, serverPort, socket.AF_INET, socket.SOCK_DGRAM)
            serverAddrTuple = addrInfo[0][-1] # (ip_string, port_int)
        except OSError as e:
            print(f"[Client] Error resolving server address {serverIp}:{serverPort}: {e}")
            return None

        # 2. Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(CLIENT_TIMEOUT_SECONDS) # In seconds

        # 3. Build DNS Query Packet
        transactionId = random.getrandbits(16) & 0xFFFF # 16-bit random TID

        header = dnsUtils.buildDnsHeader(
            tid=transactionId, qr=0, opcode=0, aa=0, tc=0, rd=1, ra=0, rcode=0,
            qdCount=1, anCount=0, nsCount=0, arCount=0
        )
        qNameEncoded = dnsUtils.encodeDomainName(domainName)
        question = dnsUtils.buildDnsQuestion(qNameEncoded, qType, dnsUtils.CLASS_IN)
        queryPacket = header + question

        # 4. Send the query
        print(f"[Client] Sending query for '{domainName}' (TID: {transactionId}) to {serverAddrTuple}")
        sock.sendto(queryPacket, serverAddrTuple)

        # 5. Receive the response
        responsePacket, _ = sock.recvfrom(dnsUtils.MAX_UDP_PAYLOAD_SIZE) # Buffer size
        print(f"[Client] Received response (len: {len(responsePacket)} bytes)")
            
        return parseDnsResponse(responsePacket, transactionId)

    except socket.timeout: # usocket.timeout is an alias for OSError with ETIMEDOUT
        print(f"[Client] Error: Request to {serverIp}:{serverPort} timed out.")
        return None
    except OSError as e: # Catch other socket/network related errors
        print(f"[Client] Socket/Network Error: {e}")
        return None
    except Exception as e:
        print(f"[Client] An unexpected error occurred in sendDnsQuery: {e}")
        return None
    finally:
        if sock:
            sock.close()


def parseDnsResponse(responsePacket, expectedTid):
    """
    Parses the DNS response packet and extracts relevant information.
    """
    try:
        header = dnsUtils.parseDnsHeader(responsePacket)
        print(f"[Client] Response Header: {header}")

        if header['id'] != expectedTid:
            print(f"[Client] Error: TID mismatch! Expected {expectedTid}, got {header['id']}")
            return None

        # RCODE in the response header indicates success or failure type from server
        if header['rcode'] != 0:
            errorMessages = {
                1: "Format Error", 2: "Server Failure", 3: "Non-Existent Domain (NXDOMAIN)",
                4: "Not Implemented", 5: "Query Refused"
            }
            errorMsg = errorMessages.get(header['rcode'], 'Unknown error code')
            print(f"[Client] DNS Server Error: RCODE {header['rcode']} ({errorMsg})")
            return {"header": header, "error": header['rcode'], "errorMessage": errorMsg, "answers": []}


        currentOffset = 12 # Start after header
        questions = []
        for _ in range(header['qdCount']):
            qName, qType, qClass, currentOffset = dnsUtils.parseDnsQuestion(responsePacket, currentOffset)
            questions.append({"name": qName, "type": qType, "class": qClass})
            print(f"[Client] Echoed Q: Name='{qName}', Type={qType}")

        answers = []
        for _ in range(header['anCount']):
            name, rType, rClass, ttl, rdLength, rDataBytes, currentOffset = dnsUtils.parseDnsRr(responsePacket, currentOffset)
            rDataFormatted = dnsUtils.formatRdata(rType, rDataBytes)
            answers.append({
                "name": name, "type": rType, "class": rClass, 
                "ttl": ttl, "rdataLength": rdLength, "rdata": rDataFormatted
            })
            print(f"[Client] Answer: Name='{name}', Type={rType}, RDATA='{rDataFormatted}'")
        
        # Could also parse NSCOUNT (Authority) and ARCOUNT (Additional) records here if needed

        return {"header": header, "questions": questions, "answers": answers}

    except ValueError as e:
        print(f"[Client] Value error parsing response: {e}")
        return None
    except Exception as e:
        print(f"[Client] An unexpected error occurred during response parsing: {e}")
        return None


if __name__ == "__main__":
    # This part is for easier testing.
    # Ensure WiFi is connected on ESP8266 before running this.
    
    # IMPORTANT: SET YOUR SERVER'S IP HERE if it's not localhost
    # e.g., if your server ESP8266 has IP 192.168.1.55
    # testServerIp = '192.168.1.24' # <<<< REPLACE WITH YOUR SERVER ESP8266's ACTUAL IP
    # If running server and client on the same ESP8266 for testing, you might use its own IP.
    # Or, if your MicroPython port supports loopback well:
    testServerIp = '127.0.0.1' 
    
    testServerPort = DEFAULT_DNS_SERVER_PORT

    print("--- DNS Client Test (MicroPython with camelCase) ---")
    print(f"Targeting server: {testServerIp}:{testServerPort}")
    print("Ensure your DNS server (dnsServerMicropython.py) is running on that address.")
    print("And ensure your ESP8266 (client) is connected to the same WiFi network.")

    # Domains to test: one local, one that should be forwarded (hopefully resolves via 8.8.8.8)
    domainsToTest = ["www.example.com", "google.com", "nonexistent.domain.for.sure"] 
    
    for domain in domainsToTest:
        print(f"\nAttempting to resolve: {domain}")
        responseData = sendDnsQuery(domain, testServerIp, testServerPort)

        if responseData and responseData.get("answers"):
            print("  Query Results:")
            for answer in responseData["answers"]:
                if answer['type'] == dnsUtils.TYPE_A:
                    print(f"    Domain: {answer['name']}  IP Address: {answer['rdata']} (TTL: {answer['ttl']})")
                else:
                    # Handle other types if your server/forwarder supports them and client parses them
                    print(f"    Domain: {answer['name']}  Type: {answer['type']}  Data: {answer['rdata']} (TTL: {answer['ttl']})")
        elif responseData and responseData.get("errorMessage"):
            print(f"  Query Failed: Server responded with error: {responseData['errorMessage']}")
        elif responseData is None: # Indicates a client-side error like timeout or socket issue
            print("  Query Failed: No response or client-side error during processing.")
        else: # Should ideally be covered by the above, but as a catch-all
            print("  Query Failed: Unknown reason or empty response.")
        print("-" * 20)
