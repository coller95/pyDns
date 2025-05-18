# dnsUtilsMicropython.py
# Adapted for MicroPython with camelCase naming

import struct
try:
    import usocket as socket
except ImportError:
    import socket # Fallback if usocket isn't explicitly needed or aliased

# DNS Record Types (Constants remain uppercase as per common convention)
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_AAAA = 28 # IPv6

# DNS Record Classes
CLASS_IN = 1


MAX_UDP_PAYLOAD_SIZE = 512

def encodeDomainName(domainName):
    """
    Encodes a domain name string into DNS label format.
    e.g., "www.example.com" -> b"\x03www\x07example\x03com\x00"
    """
    if domainName.endswith('.'):
        domainName = domainName[:-1]
    
    encoded = b""
    for label in domainName.split('.'):
        if len(label) > 63:
            raise ValueError("Label too long")
        encoded += struct.pack("!B", len(label)) + label.encode('ascii')
    encoded += b"\x00" # Null terminator for the domain name
    return encoded

def decodeDomainName(packet, offset):
    """
    Decodes a domain name from a DNS packet. Handles pointers.
    Returns (domainNameStr, newOffsetAfterName).
    """
    parts = []
    currentOffset = offset
    jumped = False
    initialOffsetAfterName = offset # Will be updated if no jump

    while True:
        lengthByte = packet[currentOffset]
        
        # Check for pointer (first two bits are 11)
        if (lengthByte & 0xC0) == 0xC0:
            if not jumped: # Only update initialOffsetAfterName if this is the first part of the name
                initialOffsetAfterName = currentOffset + 2
            
            pointerOffset = ((lengthByte & 0x3F) << 8) + packet[currentOffset + 1]
            namePart, _ = decodeDomainName(packet, pointerOffset) # Recursive call
            parts.append(namePart)
            currentOffset += 2 # Pointer is 2 bytes long
            jumped = True
            break # Pointers terminate name parsing at this level
        
        # Check for null terminator (end of name)
        elif lengthByte == 0x00:
            currentOffset += 1
            if not jumped:
                initialOffsetAfterName = currentOffset
            break
        
        # Regular label
        else:
            currentOffset += 1
            try:
                label = packet[currentOffset : currentOffset + lengthByte].decode('ascii')
            except UnicodeError: # Handle potential non-ASCII characters
                label = packet[currentOffset : currentOffset + lengthByte].decode('latin-1', 'replace')
            parts.append(label)
            currentOffset += lengthByte
            if not jumped:
                initialOffsetAfterName = currentOffset
                
    fullName = ".".join(parts)
    if not fullName.endswith('.') and fullName: # Add trailing dot if not present and not empty
        fullName += "."
        
    return fullName, initialOffsetAfterName


def buildDnsHeader(tid, qr, opcode, aa, tc, rd, ra, rcode, qdCount, anCount, nsCount, arCount):
    """Builds a DNS header."""
    flags = (qr << 15) | \
            (opcode << 11) | \
            (aa << 10) | \
            (tc << 9) | \
            (rd << 8) | \
            (ra << 7) | \
            (0 << 4) | \
            rcode # Z is 3 bits (reserved, set to 0), RCODE is 4 bits
            
    header = struct.pack("!HHHHHH", tid, flags, qdCount, anCount, nsCount, arCount)
    return header

def parseDnsHeader(packet):
    """Parses the DNS header from a packet."""
    if len(packet) < 12:
        raise ValueError("Packet too short for DNS header")
        
    tid, flags, qdCount, anCount, nsCount, arCount = struct.unpack("!HHHHHH", packet[:12])
    
    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    # z = (flags >> 4) & 0x7 # Reserved, not typically used by basic resolvers/servers
    rcode = flags & 0xF
    
    return {
        "id": tid, "qr": qr, "opcode": opcode, "aa": aa, "tc": tc, "rd": rd, 
        "ra": ra, "rcode": rcode, "qdCount": qdCount, "anCount": anCount,
        "nsCount": nsCount, "arCount": arCount
    }

def buildDnsQuestion(qNameEncoded, qType, qClass):
    """Builds a DNS question section."""
    return qNameEncoded + struct.pack("!HH", qType, qClass)

def parseDnsQuestion(packet, offset):
    """
    Parses a DNS question section from a packet starting at offset.
    Returns (qNameStr, qType, qClass, newOffset).
    """
    qName, newOffset = decodeDomainName(packet, offset)
    qType, qClass = struct.unpack("!HH", packet[newOffset : newOffset + 4])
    newOffset += 4
    return qName, qType, qClass, newOffset

def buildDnsRr(nameEncodedOrPointer, rType, rClass, ttl, rData):
    """
    Builds a DNS Resource Record.
    rData is the already packed data (e.g., packed IP address for A record).
    """
    # Name + Type + Class + TTL + RDLength
    rrHeader = nameEncodedOrPointer + struct.pack("!HHIH", rType, rClass, ttl, len(rData))
    return rrHeader + rData

def parseDnsRr(packet, offset):
    """
    Parses a DNS Resource Record from a packet starting at offset.
    Returns (nameStr, rType, rClass, ttl, rdLength, rDataBytes, newOffset).
    """
    name, newOffset = decodeDomainName(packet, offset)
    
    # Ensure there's enough data for RR header fields
    if len(packet) < newOffset + 10: # Type(2) + Class(2) + TTL(4) + RDLength(2) = 10 bytes
        raise ValueError("Packet too short for RR header fields")

    rType, rClass, ttl, rdLength = struct.unpack("!HHIH", packet[newOffset : newOffset + 10])
    newOffset += 10
    
    # Ensure there's enough data for RDATA
    if len(packet) < newOffset + rdLength: # Corrected: use rdLength here
        raise ValueError("Packet too short for RDATA")
        
    rDataBytes = packet[newOffset : newOffset + rdLength]
    newOffset += rdLength
    
    return name, rType, rClass, ttl, rdLength, rDataBytes, newOffset

def formatRdata(rType, rDataBytes):
    """Formats RDATA bytes into a human-readable string."""
    if rType == TYPE_A: # A Record (IPv4)
        if len(rDataBytes) == 4:
            try:
                # socket.inet_ntop is preferred for IPv4 as well if available
                return socket.inet_ntop(socket.AF_INET, rDataBytes)
            except Exception: # In case inet_ntop fails or AF_INET is not defined
                # Manual formatting as a fallback
                return "{}.{}.{}.{}".format(*rDataBytes)
        else:
            return "Malformed A Record RDATA (len {})".format(len(rDataBytes))
    elif rType == TYPE_AAAA: # AAAA Record (IPv6)
         if len(rDataBytes) == 16:
            try:
                if hasattr(socket, 'AF_INET6'): # Check if AF_INET6 is available
                    return socket.inet_ntop(socket.AF_INET6, rDataBytes)
                else:
                    return "AAAA Record (AF_INET6 not supported for display)"
            except Exception as e:
                 return "AAAA Record (Error formatting: {})".format(e)
         else:
            return "Malformed AAAA Record RDATA (len {})".format(len(rDataBytes))
    # For MicroPython, keep it simple for other types for now
    # Convert bytes to hex string representation
    hexRdata = "".join(["{:02x}".format(b) for b in rDataBytes])
    return "HEX:{}".format(hexRdata)

def packIpv4Address(ipStr):
    """Converts an IPv4 string ('1.2.3.4') to 4-byte bytestring."""
    try:
        # socket.inet_pton is the standard way
        return socket.inet_pton(socket.AF_INET, ipStr)
    except AttributeError: # If inet_pton is not available (older MicroPython?)
        # Manual packing if inet_pton is missing
        parts = [int(p) for p in ipStr.split('.')]
        if len(parts) != 4:
            raise ValueError("Invalid IPv4 address string for manual packing")
        for part in parts:
            if not (0 <= part <= 255):
                raise ValueError("Invalid byte in IPv4 address string for manual packing")
        return struct.pack("!BBBB", *parts)
    except Exception as e: # Catch other potential errors from inet_pton
        # Provide more context in the error message
        raise ValueError("Could not pack IP address '{}': {}".format(ipStr, e))

# (Optional) Test functions - these might be too verbose for limited memory on ESP8266
# def runTests():
#     print("Testing DNS Utils (MicroPython with camelCase)...")
#     encodedName = encodeDomainName("www.example.com")
#     assert encodedName == b'\x03www\x07example\x03com\x00'
#     print("encodeDomainName OK")
#
#     packetForDecode = b'\x00\x00' + encodedName 
#     decodedName, nextOff = decodeDomainName(packetForDecode, 2)
#     assert decodedName == "www.example.com."
#     print("decodeDomainName OK")
#
#     ipBytes = packIpv4Address("192.168.1.1")
#     assert len(ipBytes) == 4
#     formattedIp = formatRdata(TYPE_A, ipBytes)
#     # Note: The exact output of formatRdata depends on inet_ntop availability.
#     # This assertion might need adjustment if inet_ntop behaves differently or falls back.
#     assert formattedIp == "192.168.1.1" or formattedIp == "192.168.001.001" # Example variations
#     print("packIpv4Address/formatRdata OK: {}".format(formattedIp))
#     print("DNS Utils tests passed (basic).")

# if __name__ == '__main__':
# runTests() # Comment out or remove for deployment on ESP8266
