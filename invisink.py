"""invisink - invisible ink for plain text.

Hides an AES-GCM encrypted message inside ordinary text using zero-width
characters, so the carrier reads exactly as it did before. Recovering the
message requires the password.

This is steganography, not a robust watermark. It hides the fact that a message
exists; it does not survive an adversary who is looking for one. Anyone who
knows the scheme can strip every hidden bit with a one-line regular expression.
"""

import os
import shutil
import sys

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

ZWC_0 = '\u200c'  # Zero Width Non-Joiner
ZWC_1 = '\u200d'  # Zero Width Joiner

# Payload layout, big-endian:
#   MAGIC(2) | VERSION(1) | NONCE(12) | CT_LEN(2) | CIPHERTEXT(n) | TAG(16)
# The 17-byte header doubles as GCM associated data, so it is authenticated too.
MAGIC = b'ZW'  # zero-width; identifies the payload format, not the tool
VERSION = 2
NONCE_LEN = 12
CTLEN_LEN = 2
TAG_LEN = 16
HEADER_LEN = len(MAGIC) + 1 + NONCE_LEN + CTLEN_LEN
MAX_MESSAGE_LEN = 2 ** (CTLEN_LEN * 8) - 1  # bounded by the CT_LEN field

# No random salt is carried in the payload yet, which saves 16 bytes of carrier
# capacity. The cost: a given password always yields the same AES key, so
# precomputation attacks apply and an observer can tell two messages share a
# password. Restoring a random salt means writing it back into the header and
# raising the fixed overhead from 33 to 49 bytes.
FIXED_SALT = b'invisink-fixed-slt'

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1  # N=2**14 costs roughly 100 ms
KEY_LEN = 32  # AES-256

DEMO_CARRIER = "The quick brown fox jumps over the lazy dog. " * 10
DEMO_MESSAGE = "alice@example.com"
DEMO_PASSWORD = "demo passphrase"


class StegoError(Exception):
    """Base class for invisink failures."""


class NoMessageFound(StegoError):
    """The text carries no message produced by this tool."""


# ---------- bits <-> bytes ----------

def bytes_to_bits(data):
    """Iterating bytes yields ints in 0..255, so every group is exactly 8 bits.

    Formatting str characters instead would break here: any codepoint above
    U+00FF needs more than 8 bits and silently desynchronises the stream.
    """
    return ''.join(format(b, '08b') for b in data)


def bits_to_bytes(bits):
    """Discard a trailing partial byte rather than guessing at it."""
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits) - len(bits) % 8, 8))


# ---------- payload ----------

def derive_key(password):
    return scrypt(password.encode('utf-8'), FIXED_SALT, key_len=KEY_LEN,
                  N=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)


def build_payload(message, password):
    """Encrypt a message into an embeddable byte string."""
    plaintext = message.encode('utf-8')
    if len(plaintext) > MAX_MESSAGE_LEN:
        raise StegoError(f"message is {len(plaintext)} bytes, the payload "
                         f"format allows at most {MAX_MESSAGE_LEN}")

    nonce = get_random_bytes(NONCE_LEN)

    # GCM is a stream mode: no padding, so ciphertext length == plaintext length.
    header = (MAGIC + bytes([VERSION]) + nonce
              + len(plaintext).to_bytes(CTLEN_LEN, 'big'))

    cipher = AES.new(derive_key(password), AES.MODE_GCM, nonce=nonce)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return header + ciphertext + tag


def open_payload(data, password):
    """Parse and decrypt a payload.

    Raises StegoError if the password is wrong or the payload was altered.
    """
    if len(data) < HEADER_LEN + TAG_LEN or not data.startswith(MAGIC):
        raise NoMessageFound("no message marker present")

    version = data[2]
    if version != VERSION:
        raise StegoError(f"payload is v{version}, this tool only reads v{VERSION}")

    nonce = data[3:3 + NONCE_LEN]
    ct_len = int.from_bytes(data[HEADER_LEN - CTLEN_LEN:HEADER_LEN], 'big')
    header = data[:HEADER_LEN]

    end = HEADER_LEN + ct_len
    if len(data) < end + TAG_LEN:
        raise StegoError("payload is truncated, likely lost during copying")
    ciphertext, tag = data[HEADER_LEN:end], data[end:end + TAG_LEN]

    cipher = AES.new(derive_key(password), AES.MODE_GCM, nonce=nonce)
    cipher.update(header)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
    except ValueError:
        # from None: the library's MAC error adds nothing a user can act on.
        raise StegoError("authentication failed: wrong password, or the "
                         "message was tampered with") from None


# ---------- carrier encoding ----------

def strip_zwc(text):
    """Remove every zero-width character this scheme uses."""
    return ''.join(c for c in text if c not in (ZWC_0, ZWC_1))


def capacity(text):
    """How many payload bytes this carrier holds without overflowing."""
    return len(strip_zwc(text)) // 8


def overhead_for(message):
    """Total payload size in bytes for a given message."""
    return HEADER_LEN + len(message.encode('utf-8')) + TAG_LEN


def overflow_bits(text, message):
    """How many bits would spill past the end of the carrier text."""
    return max(0, overhead_for(message) * 8 - len(strip_zwc(text)))


def embed(text, payload):
    """Carry one bit in a zero-width character after each carrier character.

    A carrier that is too short is not an error: the leftover bits are appended
    to the tail instead, where they are denser and easier to notice.
    """
    clean = strip_zwc(text)
    bits = bytes_to_bits(payload)

    out = []
    i = 0
    for char in clean:
        out.append(char)
        if i < len(bits):
            out.append(ZWC_0 if bits[i] == '0' else ZWC_1)
            i += 1

    while i < len(bits):
        out.append(ZWC_0 if bits[i] == '0' else ZWC_1)
        i += 1

    return ''.join(out)


def extract_payload(text):
    bits = ''.join('0' if c == ZWC_0 else '1'
                   for c in text if c in (ZWC_0, ZWC_1))
    if not bits:
        raise NoMessageFound("text contains no zero-width characters")
    return bits_to_bytes(bits)


# ---------- public API ----------

def hide(text, message, password):
    """Return `text` with `message` encrypted and hidden inside it."""
    return embed(text, build_payload(message, password))


def reveal(text, password):
    """Return the message hidden in `text`, or raise StegoError."""
    return open_payload(extract_payload(text), password)


def detect(text):
    """Report whether a message is present, without needing the password."""
    try:
        return extract_payload(text).startswith(MAGIC)
    except NoMessageFound:
        return False


# ---------- banner ----------

_LOGO = [
    "██╗███╗   ██╗██╗   ██╗██╗███████╗██╗███╗   ██╗██╗  ██╗",
    "██║████╗  ██║██║   ██║██║██╔════╝██║████╗  ██║██║ ██╔╝",
    "██║██╔██╗ ██║██║   ██║██║███████╗██║██╔██╗ ██║█████╔╝ ",
    "██║██║╚██╗██║╚██╗ ██╔╝██║╚════██║██║██║╚██╗██║██╔═██╗ ",
    "██║██║ ╚████║ ╚████╔╝ ██║███████║██║██║ ╚████║██║  ██╗",
    "╚═╝╚═╝  ╚═══╝  ╚═══╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝",
]
_LOGO_WIDTH = max(len(line) for line in _LOGO)
_TAGLINE = "invisible ink for plain text  ·  AES-GCM + scrypt"


def _colour_enabled():
    """Honour the NO_COLOR convention, and stay plain when piped to a file."""
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _inked(line):
    """Shade a line dark to light, so the logo reads as ink developing."""
    out = []
    for i, char in enumerate(line):
        if char == ' ':
            out.append(char)
            continue
        shade = 238 + int(i / max(1, _LOGO_WIDTH - 1) * 17)
        out.append(f"\033[38;5;{shade}m{char}")
    return ''.join(out) + "\033[0m"


def banner():
    if shutil.get_terminal_size(fallback=(80, 24)).columns < _LOGO_WIDTH + 2:
        print(f"\n  · · ·  i n v i s i n k  · · ·\n  {_TAGLINE}")
        return

    print()
    if _colour_enabled():
        for line in _LOGO:
            print(_inked(line))
        print(f"      \033[2m{_TAGLINE}\033[0m")
    else:
        for line in _LOGO:
            print(line)
        print(f"      {_TAGLINE}")


# ---------- console interface ----------

def _menu_hide():
    carrier = input("\nType the carrier text:\n") or DEMO_CARRIER
    message = input("\nType the message to hide: ") or DEMO_MESSAGE
    password = input("Enter the encryption password: ") or DEMO_PASSWORD

    spill = overflow_bits(carrier, message)
    print(f"\nCapacity: needs {overhead_for(message) * 8} characters, "
          f"carrier has {len(strip_zwc(carrier))}")
    if spill:
        print(f"Warning: carrier is short, {spill} bits will cluster at the tail, "
              f"where dense zero-width characters are easier to spot.")

    try:
        inked = hide(carrier, message, password)
    except StegoError as e:
        print(f"\nFailed: {e}")
        return

    print("\nText with hidden message (visually identical):\n", inked)
    print("\nWith invisible characters shown (repr):\n", repr(inked))


def _menu_reveal():
    text = input("\nPaste the text containing a hidden message:\n")
    password = input("\nEnter the decryption password: ") or DEMO_PASSWORD
    try:
        print(f"\nRevealed message: {reveal(text, password)}")
    except StegoError as e:
        print(f"\nFailed: {e}")


def _menu_detect():
    text = input("\nPaste the text to check:\n")
    if detect(text):
        print("\nHidden message detected (the password is still needed to read it).")
    else:
        print("\nNo hidden message found.")


def main():
    banner()
    actions = {"1": _menu_hide, "2": _menu_reveal, "3": _menu_detect}
    while True:
        print()
        print("1. Hide a message")
        print("2. Reveal a message")
        print("3. Detect a message (no password needed)")
        print("4. Exit\n")
        choice = input("Choose (1/2/3/4): ").strip()
        if choice == "4":
            print("\nGoodbye.")
            break
        action = actions.get(choice)
        if action:
            action()
        else:
            print("\nInvalid input, please choose 1-4.")


if __name__ == '__main__':
    main()
