import re
from binascii import a2b_base64, b2a_base64

def PEMEncode(data, marker):
    """Encode a piece of binary data into PEM format.

    Args:
      data (byte string):
        The piece of binary data to encode.
      marker (string):
        The marker for the PEM block (e.g. "PUBLIC KEY").
        Note that there is no official master list for all allowed markers.
        Still, you can refer to the OpenSSL_ source code.

    Returns:
      The PEM block, as a string.
    """
    out = "-----BEGIN %s-----\n" % marker

    # Each BASE64 line can take up to 64 characters (=48 bytes of data)
    # b2a_base64 adds a new line character!
    chunks = [b2a_base64(data[i:i + 48]) for i in range(0, len(data), 48)]
    out += "".join(chunks)
    out += "-----END %s-----" % marker
    return out

def PEMDecode(pem_data):
    """Decode a PEM block into binary.

    Args:
      pem_data (string):
        The PEM block.

    Returns:
      A tuple with the binary data, the marker string, and a boolean to
      indicate if decryption was performed.

    Raises:
      ValueError: if decoding fails, if the PEM file is encrypted and no passphrase has
                  been provided or if the passphrase is incorrect.
    """

    # Verify Pre-Encapsulation Boundary
    r = re.compile(r"\s*-----BEGIN (.*)-----\s+")
    m = r.match(pem_data)
    if not m:
        raise ValueError("Not a valid PEM pre boundary")
    marker = m.group(1)

    # Verify Post-Encapsulation Boundary
    r = re.compile(r"-----END (.*)-----\s*$")
    m = r.search(pem_data)
    if not m or m.group(1) != marker:
        raise ValueError("Not a valid PEM post boundary")

    # Removes spaces and slit on lines
    lines = pem_data.replace(" ", '').split()

    # Decode body
    data = a2b_base64(''.join(lines[1:-1]))

    return (data, marker)