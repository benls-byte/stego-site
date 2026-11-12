"""Crypto Corgi - a Drafter-based image steganography project.

The app hides UTF-8 text in the least-significant bits of an image's RGB
channels. The encoded image is downloaded as PNG so the hidden bits are not
lost to JPEG compression.

The optional passphrase mode is an educational, standard-library-only
obfuscation/integrity demonstration. It is NOT a substitute for an audited
cryptography library when protecting sensitive information.
"""

from dataclasses import dataclass
import hashlib
import hmac
import secrets

from drafter import *


# ---------------------------------------------------------------------------
# Application state
# ---------------------------------------------------------------------------

@dataclass
class State:
    # Status and navigation state
    status_message: str = "Ready to hide or reveal a message."
    is_success: bool = True

    # Encoding state
    current_image_path: str = ""
    secret_text: str = ""
    output_image_path: str = ""

    # Decoding state
    decoded_text: str = ""
    passphrase: str = ""

    # Extra display value: Drafter can keep a Picture in State and display it.
    output_image_preview: Picture | None = None


# ---------------------------------------------------------------------------
# Steganography and passphrase helpers
# ---------------------------------------------------------------------------

MAGIC = b"CCSG1"                  # Identifies a Crypto Corgi message.
HEADER_SIZE = len(MAGIC) + 1 + 4  # Magic + mode byte + 4-byte payload length.
PLAIN_MODE = b"P"
PASSPHRASE_MODE = b"E"
SALT_SIZE = 16
NONCE_SIZE = 16
TAG_SIZE = 32
PBKDF2_ITERATIONS = 150_000


def derive_keys(passphrase: str, salt: bytes) -> tuple[bytes, bytes]:
    """Create separate encryption-stream and authentication keys."""
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=64,
    )
    return derived[:32], derived[32:]


def xor_with_hmac_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    """XOR data with a deterministic HMAC-SHA256 keystream."""
    result = bytearray()
    for counter, start in enumerate(range(0, len(data), 32)):
        block = hmac.new(
            key,
            nonce + counter.to_bytes(8, "big"),
            hashlib.sha256,
        ).digest()
        chunk = data[start:start + 32]
        result.extend(byte ^ mask for byte, mask in zip(chunk, block))
    return bytes(result)


def make_message_payload(message: str, passphrase: str) -> bytes:
    """Build a header and message body that can be placed into image bits."""
    message_bytes = message.encode("utf-8")

    if passphrase:
        mode = PASSPHRASE_MODE
        salt = secrets.token_bytes(SALT_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)
        encryption_key, authentication_key = derive_keys(passphrase, salt)
        encrypted_message = xor_with_hmac_stream(
            message_bytes, encryption_key, nonce
        )

        body_without_tag = salt + nonce + encrypted_message
        tag = hmac.new(
            authentication_key,
            MAGIC + mode + body_without_tag,
            hashlib.sha256,
        ).digest()
        body = body_without_tag + tag
    else:
        mode = PLAIN_MODE
        # A checksum detects accidental corruption for unprotected messages.
        checksum = hashlib.sha256(message_bytes).digest()[:16]
        body = message_bytes + checksum

    if len(body) > 0xFFFFFFFF:
        raise ValueError("That message is too large to encode.")

    header = MAGIC + mode + len(body).to_bytes(4, "big")
    return header + body


def embed_bytes(picture: Picture, data: bytes) -> None:
    """Embed bytes by replacing the least-significant RGB bits in a Picture."""
    total_bits = len(data) * 8
    capacity_bits = picture.width * picture.height * 3

    if total_bits > capacity_bits:
        available_bytes = max(0, capacity_bits // 8 - HEADER_SIZE)
        raise ValueError(
            "This image is too small for that message. Try a larger image or "
            "a shorter message. Approximate message capacity: "
            + str(available_bytes)
            + " bytes."
        )

    bit_position = 0

    for y in range(picture.height):
        for x in range(picture.width):
            if bit_position >= total_bits:
                return

            pixel = list(picture.get_pixel(x, y))
            changed = False

            for channel in range(3):
                if bit_position >= total_bits:
                    break

                byte_index = bit_position // 8
                bit_offset = 7 - (bit_position % 8)
                bit = (data[byte_index] >> bit_offset) & 1

                pixel[channel] = (pixel[channel] & 0xFE) | bit
                bit_position += 1
                changed = True

            if changed:
                picture.set_pixel(x, y, tuple(pixel))


def read_embedded_bytes(
    picture: Picture, start_bit: int, byte_count: int
) -> bytes:
    """Read a selected number of bytes beginning at a channel-bit position."""
    if byte_count < 0:
        raise ValueError("The hidden message has an invalid length.")

    required_bits = byte_count * 8
    total_bits = picture.width * picture.height * 3
    if start_bit + required_bits > total_bits:
        raise ValueError("The image does not contain a complete hidden message.")

    result = bytearray()
    current_byte = 0
    bits_in_current_byte = 0

    first_pixel = start_bit // 3
    first_channel = start_bit % 3
    pixel_count = picture.width * picture.height

    for pixel_index in range(first_pixel, pixel_count):
        x = pixel_index % picture.width
        y = pixel_index // picture.width
        pixel = picture.get_pixel(x, y)
        channel_start = first_channel if pixel_index == first_pixel else 0

        for channel in range(channel_start, 3):
            bit = pixel[channel] & 1
            current_byte = (current_byte << 1) | bit
            bits_in_current_byte += 1

            if bits_in_current_byte == 8:
                result.append(current_byte)
                current_byte = 0
                bits_in_current_byte = 0

                if len(result) == byte_count:
                    return bytes(result)

    raise ValueError("The image does not contain a complete hidden message.")


def encode_image(image_bytes: bytes, message: str, passphrase: str) -> bytes:
    """Return a PNG containing the hidden message."""
    if not image_bytes:
        raise ValueError("Please choose an image first.")
    if not message.strip():
        raise ValueError("Please enter a secret message before encoding.")

    picture = Picture.from_bytes(image_bytes)
    payload = make_message_payload(message, passphrase)
    embed_bytes(picture, payload)
    return picture.to_bytes()


def decode_image(image_bytes: bytes, passphrase: str) -> str:
    """Extract and verify a hidden message from an encoded image."""
    if not image_bytes:
        raise ValueError("Please choose an encoded image first.")

    picture = Picture.from_bytes(image_bytes)
    if picture.width * picture.height * 3 < HEADER_SIZE * 8:
        raise ValueError("This image is too small to contain a Crypto Corgi message.")

    header = read_embedded_bytes(picture, 0, HEADER_SIZE)
    if header[:len(MAGIC)] != MAGIC:
        raise ValueError(
            "No Crypto Corgi message was found. Make sure you selected the "
            "encoded PNG image."
        )

    mode = header[len(MAGIC):len(MAGIC) + 1]
    payload_length = int.from_bytes(header[-4:], "big")
    payload = read_embedded_bytes(picture, HEADER_SIZE * 8, payload_length)

    if mode == PLAIN_MODE:
        if len(payload) < 16:
            raise ValueError("The hidden message is incomplete or damaged.")
        message_bytes = payload[:-16]
        saved_checksum = payload[-16:]
        actual_checksum = hashlib.sha256(message_bytes).digest()[:16]
        if not hmac.compare_digest(saved_checksum, actual_checksum):
            raise ValueError("The hidden message appears to be damaged.")

    elif mode == PASSPHRASE_MODE:
        if not passphrase:
            raise ValueError("This message is passphrase-protected. Enter its passphrase.")
        if len(payload) < SALT_SIZE + NONCE_SIZE + TAG_SIZE:
            raise ValueError("The passphrase-protected message is incomplete.")

        salt = payload[:SALT_SIZE]
        nonce = payload[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        encrypted_message = payload[SALT_SIZE + NONCE_SIZE:-TAG_SIZE]
        saved_tag = payload[-TAG_SIZE:]

        encryption_key, authentication_key = derive_keys(passphrase, salt)
        body_without_tag = payload[:-TAG_SIZE]
        actual_tag = hmac.new(
            authentication_key,
            MAGIC + mode + body_without_tag,
            hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(saved_tag, actual_tag):
            raise ValueError("The passphrase is incorrect or the image was changed.")

        message_bytes = xor_with_hmac_stream(
            encrypted_message, encryption_key, nonce
        )
    else:
        raise ValueError("This image uses an unknown message format.")

    try:
        return message_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("The hidden message could not be read as text.") from error


# ---------------------------------------------------------------------------
# Drafter routes: the five pages and two processing handlers
# ---------------------------------------------------------------------------

@route
def index(state: State) -> Page:
    return Page(state, [
        Header("Comp Sci Final Project - Steganography Tool"),
        Paragraph(
            "Hide secret messages inside images or reveal hidden text from "
            "image files. Choose what you want to do below."
        ),
        HorizontalRule(),
        Header("What would you like to do?"),
        Button("Hide Secret Message (Encode)", "encode_page"),
        Button("Reveal Hidden Message (Decode)", "decode_page"),
        HorizontalRule(),
        Paragraph(
            "Tip: The encoded image is saved as a PNG. Use that PNG when you "
            "decode the message; JPEG compression can destroy hidden data."
        ),
    ])


@route
def encode_page(state: State) -> Page:
    return Page(state, [
        Header("Encode a Secret Message"),
        Paragraph("Choose an image, type your message, and optionally add a passphrase."),
        "Image file (PNG or JPEG):",
        FileUpload("image", accept="image/*"),
        "Secret message:",
        TextArea("text", state.secret_text, rows=6),
        "Passphrase (optional):",
        TextBox("key", "", kind="password"),
        Paragraph(
            "A passphrase makes the message unreadable without the same "
            "passphrase. This classroom demo is not intended for highly "
            "sensitive information."
        ),
        Button("Process Encoding", "process_encode"),
        Button("Back to Home", "index"),
    ])


@route
def process_encode(
    state: State, image: bytes | None, text: str, key: str
) -> Redirect:
    state.is_success = False
    state.output_image_preview = None
    state.output_image_path = ""
    state.status_message = "Encoding did not finish."
    state.secret_text = text
    state.passphrase = key

    try:
        if image is None:
            raise ValueError("Please choose an image to upload.")

        encoded_bytes = encode_image(image, text, key)
        state.current_image_path = "uploaded image (kept in memory)"
        state.output_image_path = "crypto_corgi_encoded.png"
        state.output_image_preview = Picture.from_bytes(encoded_bytes)
        state.status_message = "Image encoded successfully!"
        state.is_success = True
    except Exception as error:
        state.status_message = str(error)
    finally:
        # Do not keep the passphrase in application state after processing.
        state.passphrase = ""

    return Redirect("encode_result_page")


@route
def encode_result_page(state: State) -> Page:
    content = [Header("Encoding Results")]

    if state.is_success and state.output_image_preview is not None:
        content.extend([
            Paragraph("Encoding Complete! Your message is now hidden in the image."),
            Image(state.output_image_preview, 500, alt="Encoded image preview"),
            Download(
                "Download Encoded Image",
                state.output_image_path,
                state.output_image_preview.to_bytes(),
                content_type="image/png",
            ),
        ])
    else:
        content.append(Paragraph("Encoding failed: " + state.status_message))

    content.extend([
        Button("Encode Another Image", "encode_page"),
        Button("Back to Home", "index"),
    ])
    return Page(state, content)


@route
def decode_page(state: State) -> Page:
    return Page(state, [
        Header("Decode a Secret Message"),
        Paragraph("Upload the PNG image that was created by Crypto Corgi."),
        "Encoded image file:",
        FileUpload("image", accept="image/*"),
        "Passphrase (only needed if one was used during encoding):",
        TextBox("key", "", kind="password"),
        Button("Extract Secret", "process_decode"),
        Button("Back to Home", "index"),
    ])


@route
def process_decode(
    state: State, image: bytes | None, key: str
) -> Redirect:
    state.is_success = False
    state.decoded_text = ""
    state.status_message = "Decoding did not finish."
    state.passphrase = key

    try:
        if image is None:
            raise ValueError("Please choose an encoded image to upload.")

        state.current_image_path = "uploaded encoded image (kept in memory)"
        state.decoded_text = decode_image(image, key)
        state.status_message = "Message decoded successfully!"
        state.is_success = True
    except Exception as error:
        state.status_message = str(error)
    finally:
        # Do not keep the passphrase in application state after processing.
        state.passphrase = ""

    return Redirect("decode_result_page")


@route
def decode_result_page(state: State) -> Page:
    content = [Header("Extraction Results")]

    if state.is_success:
        content.extend([
            Paragraph("Message Decoded Successfully!"),
            Paragraph("Extracted Message:"),
            PreformattedText(state.decoded_text),
        ])
    else:
        content.append(Paragraph("Decoding failed: " + state.status_message))

    content.extend([
        Button("Decode Another Image", "decode_page"),
        Button("Back to Home", "index"),
    ])
    return Page(state, content)


# Start the website. Drafter serves the routes above.
start_server(State())

