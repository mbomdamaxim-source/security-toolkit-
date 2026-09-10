"""Educational cryptography logic for the Credential Auditor learning panel.

Two kinds of content live here, clearly separated:
* Classic, insecure ciphers (Caesar, Vigenere) and Base64 are taught as
  history: they exist to be broken, never to protect real data.
* Real modern cryptography (SHA-256, PBKDF2, AES-256-GCM) always uses
  audited standard libraries. This project never implements its own
  "secure" crypto.
"""
from dataclasses import dataclass
import base64
import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERATIONS = 200_000
KEY_LENGTH = 32  # bytes -> AES-256

_CIPHER_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def _normalise_key(key: str) -> str:
    letters = "".join(character for character in key.upper() if character.isalpha())
    if not letters:
        raise ValueError("Enter a keyword containing at least one letter.")
    return letters


def caesar(text: str, shift: int, decrypt: bool = False) -> str:
    """Caesar cipher over A-Z, preserving case and non-letter characters.

    Educational only: a Caesar cipher has only 25 possible shifts and is
    broken instantly by brute force or frequency analysis.
    """
    if not isinstance(shift, int) or isinstance(shift, bool):
        raise ValueError("Shift must be a whole number.")
    offset = (-shift if decrypt else shift) % 26
    result = []
    for character in text:
        if character.isalpha():
            base = ord("A") if character.isupper() else ord("a")
            result.append(chr(base + (ord(character) - base + offset) % 26))
        else:
            result.append(character)
    return "".join(result)


def caesar_break(text: str) -> list[tuple[int, str]]:
    """Try every Caesar shift and return [(shift, result), ...] for 1..25.

    Educational only: shows in one view why a Caesar cipher is trivially
    broken — one of the 25 outputs is always the plaintext.
    """
    return [(shift, caesar(text, shift)) for shift in range(1, 26)]


def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    """Vigenere cipher over A-Z (key letters only), preserving case.

    Educational only: a Vigenere cipher with a short keyword falls to
    Kasiski examination and frequency analysis.
    """
    key_letters = _normalise_key(key)
    result = []
    key_index = 0
    for character in text:
        if character.isalpha():
            base = ord("A") if character.isupper() else ord("a")
            shift = ord(key_letters[key_index % len(key_letters)]) - ord("A")
            if decrypt:
                shift = -shift
            result.append(chr(base + (ord(character) - base + shift) % 26))
            key_index += 1
        else:
            result.append(character)
    return "".join(result)


def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def base64_decode(data: str) -> str:
    try:
        return base64.b64decode(data.encode("ascii"), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("That is not valid Base64 text.") from error


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 key derivation; turns a passphrase into a key."""
    if not passphrase:
        raise ValueError("Enter a passphrase first.")
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=KEY_LENGTH)


def aes_gcm_encrypt(passphrase: str, plaintext: str) -> tuple[bytes, bytes, bytes]:
    """Encrypt text with AES-256-GCM. Returns (salt, nonce, ciphertext).

    The salt is used to derive the key from the passphrase; the nonce is
    random per message. Both are needed for decryption and are not secret.
    """
    if not plaintext:
        raise ValueError("Enter a message to encrypt.")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return salt, nonce, ciphertext


def aes_gcm_decrypt(passphrase: str, salt: bytes, nonce: bytes, ciphertext: bytes) -> str:
    """Decrypt AES-256-GCM text. Raises ValueError if the data was tampered with."""
    key = derive_key(passphrase, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as error:
        raise ValueError("Decryption failed: the passphrase is wrong or the data was modified.") from error
    return plaintext.decode("utf-8")


@dataclass(frozen=True)
class CryptoQuestion:
    identifier: int
    category: str
    question_text: str
    correct_answer: str
    explanation: str


def hash_with_salt(password: str, salt_hex: str | None = None) -> tuple[str, str]:
    """Return (salt_hex, hash_hex) using PBKDF2-HMAC-SHA256.

    The same password hashed with two different salts produces two different
    hashes. That is exactly why salted hashing defeats precomputed rainbow
    tables: an attacker cannot reuse one lookup table for every account.
    """
    if not password:
        raise ValueError("Enter a password to hash.")
    salt = bytes.fromhex(salt_hex) if salt_hex else os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=KEY_LENGTH
    )
    return salt.hex(), digest.hex()


def verify_salted_hash(password: str, salt_hex: str, hash_hex: str) -> bool:
    """Re-derive the hash and compare; used by the 'verify' step of the demo."""
    try:
        _, computed = hash_with_salt(password, salt_hex)
    except ValueError:
        return False
    return computed == hash_hex.lower()


def rsa_generate_keypair() -> tuple[bytes, bytes]:
    """Generate an RSA-2048 key pair. Returns (private_pem, public_pem).

    Educational demo: real deployments generate and protect private keys on
    the user's device, and the private key never leaves it.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _rsa_oaep_padding():
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def rsa_encrypt(public_pem: bytes, plaintext: str) -> str:
    """Encrypt with an RSA public key (RSA-OAEP-SHA256)."""
    public_key = serialization.load_pem_public_key(public_pem)
    ciphertext = public_key.encrypt(plaintext.encode("utf-8"), _rsa_oaep_padding())
    return base64.b64encode(ciphertext).decode("ascii")


def rsa_decrypt(private_pem: bytes, ciphertext_b64: str) -> str:
    """Decrypt with an RSA private key. Fails if the key does not match."""
    private_key = serialization.load_pem_private_key(private_pem, password=None)
    try:
        plaintext = private_key.decrypt(
            base64.b64decode(ciphertext_b64), _rsa_oaep_padding()
        )
    except Exception as error:
        raise ValueError("Decryption failed: wrong private key or corrupted ciphertext.") from error
    return plaintext.decode("utf-8")


# Fixed, reviewed question bank. Every answer is verified by
# verify_crypto_quiz_bank() before it is used.
_RAW_CRYPTO_BANK = '''
1|symmetric_asymmetric|Which encryption algorithm uses the same key for encryption and decryption?|AES|AES is a symmetric cipher: the same key both encrypts and decrypts. RSA and Diffie-Hellman are asymmetric.
2|symmetric_asymmetric|AES-256 uses a key of how many bits?|256|The number after AES- is the key length in bits: AES-128, AES-192 and AES-256 use 128, 192 and 256-bit keys.
3|symmetric_asymmetric|Which of these is an asymmetric (public-key) algorithm?|RSA|RSA uses a public/private key pair, so it is asymmetric. AES is symmetric; SHA-256 is a hash.
4|symmetric_asymmetric|In RSA, which key decrypts a message encrypted with the public key?|private key|Only the matching private key can decrypt what the public key encrypted. The private key must never be shared.
5|symmetric_asymmetric|Why does TLS use symmetric encryption for the bulk data?|It is much faster than asymmetric encryption|Asymmetric maths is slow, so TLS uses it only for the handshake, then switches to fast symmetric encryption for the data.
6|symmetric_asymmetric|Which statement about asymmetric encryption is true?|It uses a matching public and private key pair|In asymmetric crypto the public key encrypts or verifies and the private key decrypts or signs; they always come as a pair.
7|symmetric_asymmetric|Which of these is a symmetric block cipher?|AES-256|AES-256 is a block cipher: it encrypts fixed-size blocks with a 256-bit key. RSA and Diffie-Hellman are asymmetric.
8|symmetric_asymmetric|What is a block cipher?|It encrypts data in fixed-size blocks|A block cipher processes data in fixed-size chunks (128-bit blocks for AES) instead of one character at a time.
9|symmetric_asymmetric|Which of these is a symmetric cipher used in modern TLS?|ChaCha20|ChaCha20 is a modern symmetric stream cipher; TLS 1.3 offers it alongside AES-GCM. RSA is asymmetric.
10|symmetric_asymmetric|In hybrid encryption, asymmetric keys are used to...|exchange a symmetric session key|Hybrid encryption uses asymmetric keys just to agree a session key; the bulk data then flows under fast symmetric encryption.
11|hashing|SHA-256 produces a digest of how many bits?|256|The number after SHA- is the digest length: SHA-256 always outputs 256 bits (64 hex characters).
12|hashing|What property means a hash function cannot be reversed to recover the input?|One-way|A one-way function is easy to compute but practically impossible to invert: from a hash you cannot recover the input.
13|hashing|What does the avalanche effect describe?|A tiny input change produces a completely different hash|Changing one character flips about half the output bits, so similar inputs give unrelated hashes.
14|hashing|Why is salt added before hashing passwords?|It defeats precomputed rainbow tables|A per-user random salt makes each hash unique, so an attacker cannot reuse one precomputed table for all accounts.
15|hashing|Which of these is a hashing algorithm?|SHA-256|SHA-256 is a cryptographic hash. AES and ChaCha20 are encryption ciphers, not hashes.
16|hashing|Hashing is primarily used for which purpose?|Verifying data integrity|A hash is a fingerprint: if the data changes, the hash changes, so tampering is detected.
17|hashing|What is a salt in password hashing?|Random data added before hashing|The salt is mixed with the password before hashing so identical passwords produce different hashes.
18|hashing|Which property prevents an attacker from finding the input of a hash?|Preimage resistance|Preimage resistance means it is infeasible to find any input that produces a given hash.
19|hashing|What happens if you hash the same input twice with SHA-256?|You get the same digest|Hashing is deterministic: the same input always yields the same output. Salts exist to vary password hashes.
20|hashing|Which of these is NOT a hashing algorithm?|AES|AES is a cipher used for encryption; it is reversible with a key. Hashes like SHA-256 are one-way.
21|tls_https|What does HTTPS use to protect data in transit?|TLS|HTTPS is HTTP over TLS: the TLS layer encrypts and authenticates the traffic.
22|tls_https|Which port does HTTPS use by default?|443|By default, HTTPS servers listen on TCP port 443 (HTTP uses 80).
23|tls_https|What does the padlock icon in a browser indicate?|The connection is encrypted with TLS|The padlock means the current connection uses a valid TLS session, so traffic is encrypted and the server is authenticated.
24|tls_https|What is the main purpose of a TLS certificate?|To verify the server's identity|The certificate binds a public key to an identity and is signed by a trusted CA, so the client knows who it is talking to.
25|tls_https|TLS provides which two properties for web traffic?|Confidentiality and integrity|TLS encrypts the traffic (confidentiality) and authenticates it (integrity): tampered data fails to verify.
26|tls_https|What is a certificate authority (CA)?|A trusted organisation that issues digital certificates|CAs sign certificates, letting clients verify that a public key really belongs to the named site.
27|tls_https|What does TLS stand for?|Transport Layer Security|TLS (Transport Layer Security) is the modern protocol; its predecessor was SSL.
28|tls_https|Which protocol did TLS replace?|SSL|SSL (Secure Sockets Layer) was the older protocol; TLS is its successor and is what HTTPS uses today.
29|tls_https|What happens if a website's TLS certificate is expired?|The browser warns the user|An expired certificate cannot be validated, so the browser blocks or warns instead of trusting the connection.
30|tls_https|What is a TLS handshake used for?|To agree on keys and a cipher suite|During the handshake the client and server authenticate and agree on the session keys and algorithms for the session.
31|classic_ciphers|Using a Caesar cipher with shift 3, what is CAT encrypted as?|FDW|Each letter moves 3 places forward: C->F, A->D, T->W. Only letters shift; other characters stay.
32|classic_ciphers|Using a Caesar cipher with shift 3, what does FDW decrypt to?|CAT|Decrypting with shift 3 moves each letter 3 places back: F->C, D->A, W->T.
33|classic_ciphers|ROT13 is a Caesar cipher with a shift of...|13|ROT13 shifts by 13, exactly half the alphabet, so encrypting and decrypting are the same operation.
34|classic_ciphers|Which cipher varies the shift for each letter using a keyword?|Vigenere|The Vigenere cipher uses a keyword to pick a different shift for every letter, making it a polyalphabetic cipher.
35|classic_ciphers|How many possible shifts does a standard Caesar cipher have?|25|There are 25 non-trivial shifts (1-25); shift 0 leaves the text unchanged, so the key space is tiny.
36|classic_ciphers|Why are classic ciphers like Caesar and Vigenere insecure today?|They can be broken with frequency analysis and brute force|With only 25 Caesar keys or a short keyword, a computer tries everything and matches letter frequencies in seconds.
37|classic_ciphers|What is the key space of a Caesar cipher?|25 possible shifts|A tiny key space means brute force is trivial: try every shift and read the plaintext.
38|classic_ciphers|What is frequency analysis?|Analysing letter frequencies to break ciphers|In most languages some letters are much more common, so matching frequency patterns reveals the substitution.
39|classic_ciphers|Which of these is a polyalphabetic cipher?|Vigenere|Polyalphabetic ciphers use multiple substitution alphabets; Vigenere switches alphabet with each letter via the keyword.
40|classic_ciphers|What is the main weakness of the Vigenere cipher with a short keyword?|The keyword repeats, creating patterns|A repeated keyword leaks periodic patterns that Kasiski examination and frequency analysis can exploit.
41|encoding|Base64 is best described as...|An encoding, not encryption|Base64 only changes how bytes are represented; it needs no key and provides no secrecy.
42|encoding|Is Base64 encryption?|No, it is reversible without any key|Anyone can decode Base64 with a simple algorithm; encryption requires a secret key to reverse.
43|encoding|What is the purpose of encoding?|To represent data in a different format for transport|Encoding converts data so it survives transport (e.g. binary in text or URLs); it is not secrecy.
44|encoding|Which technique provides confidentiality?|Encryption|Confidentiality (secrecy) comes from encryption with a key. Encoding only changes the format.
45|encoding|A secret key is needed to...|Decrypt an encrypted message|Encryption scrambles data with a key; only the correct key can decrypt it back to plaintext.
46|encoding|What can anyone do to a Base64 string?|Decode it without a key|Decoding needs no secret, which is why Base64 must never be used to protect sensitive data.
47|encoding|Which of these is an encoding scheme?|Base64|Base64, hex and URL encoding are formats; AES and RSA are encryption algorithms.
48|encoding|What does the '64' in Base64 mean?|It uses 64 characters to represent data|Base64 uses 64 symbols (A-Z, a-z, 0-9, +, /) plus padding '=' to encode binary as text.
49|encoding|Can you encrypt data without a key?|No, encryption always requires a key|Encryption without a key is not encryption: any reversible, keyless transformation is just encoding.
50|encoding|What is the difference between encoding and encryption?|Encoding has no key; encryption requires a key|The key is the whole difference: encoding is reversible by anyone, encryption only by key holders.
51|key_security|Where should you store long-term passwords and keys?|In a password manager with a strong master password|A password manager encrypts the vault with a strong master password and generates unique passwords per site.
52|key_security|What is key rotation?|Replacing a key after a set period of use|Rotating keys limits the damage if a key leaks and reduces the amount of data a single key protects.
53|key_security|Two-factor authentication adds...|A second factor beyond the password|2FA needs something you know (the password) plus something you have or are (a code, an app, a fingerprint).
54|key_security|Why should you never reuse passwords across websites?|A breach of one site would expose your other accounts|If one site leaks the password, attackers try it everywhere (credential stuffing); reuse magnifies every breach.
55|key_security|Writing your password on a sticky note is...|A security risk|A visible password lets anyone nearby steal it; use a password manager instead.
56|key_security|Which habit creates the strongest passwords?|A unique random password for every account|Randomness and uniqueness defeat guessing, dictionary attacks and credential stuffing.
57|key_security|What is a passphrase?|A longer phrase used as a password|A passphrase like 'correct horse battery staple' is long, memorable and much harder to crack than a short word.
58|key_security|Why should you enable two-factor authentication?|It protects the account even if the password leaks|With 2FA a stolen password alone is not enough; the attacker still needs the second factor.
59|key_security|What is a password manager?|A tool that stores and generates unique passwords|It keeps every account's random password in an encrypted vault unlocked by one master password.
60|key_security|When should you change a password immediately?|When you suspect it was compromised|If a site announces a breach or you shared the password, change it right away; do not wait for a schedule.
61|digital_signatures|What does a digital signature prove?|The message is authentic and was not modified|Signing hashes the message and encrypts the hash with the private key; verifying with the public key proves origin and integrity.
62|digital_signatures|Which key is used to create a digital signature?|private key|Only the signer's private key can create a valid signature; anyone with the public key can verify it.
63|digital_signatures|Which key is used to verify a digital signature?|public key|Verification uses the public key to check the signature, so anyone can confirm authenticity without the secret.
64|digital_signatures|How is a message typically signed?|Hash the message, then encrypt the hash with the private key|Signing a hash is fast and small; the signature covers the digest and thereby the whole message.
65|digital_signatures|Digital signatures provide which properties?|Authenticity, integrity and non-repudiation|They prove who sent it (authenticity), that it was unchanged (integrity) and that the sender cannot deny it (non-repudiation).
66|digital_signatures|What is non-repudiation?|The signer cannot deny having signed the message|Because only the signer's private key produces the signature, they cannot later claim they did not sign it.
67|digital_signatures|What is a hash used for in a digital signature?|To create a fixed-size digest of the message|Hashing first makes signing fast and gives every message a small, unique fingerprint to protect.
68|digital_signatures|Which statement about digital signatures is true?|They are computationally infeasible to forge|Without the private key, producing a valid signature for a chosen message is infeasible, which is the security guarantee.
69|digital_signatures|What happens if the message changes after it was signed?|Signature verification fails|The hash no longer matches, so verifying with the public key fails; tampering is detected.
70|digital_signatures|Who can verify a digital signature?|Anyone with the signer's public key|The public key is public by design, so any recipient can verify authenticity and integrity.
71|key_exchange|What is the purpose of key exchange?|To agree on a shared secret over an insecure channel|Key exchange lets two parties end up with the same secret key without sending it, even if someone listens.
72|key_exchange|Which algorithm is commonly used for key exchange in TLS?|Diffie-Hellman|Diffie-Hellman (and its elliptic-curve variant ECDHE) is the standard key-exchange algorithm in modern TLS.
73|key_exchange|What does Diffie-Hellman allow two parties to do?|Agree on a shared secret without ever sending it|Each side combines its private value with the other's public value; both compute the same secret that never crossed the wire.
74|key_exchange|Why is asymmetric encryption used at the start of a TLS session?|To exchange a session key for faster symmetric encryption|The handshake uses asymmetric crypto just to agree the session key; bulk data then flows under fast symmetric encryption.
75|key_exchange|What does perfect forward secrecy ensure?|Past session keys stay secret even if the long-term key leaks|Ephemeral keys mean each session key is unique and discarded, so compromising one key does not reveal past sessions.
76|key_exchange|What is a session key?|A temporary symmetric key used for one communication session|A fresh session key is generated per session and destroyed afterwards, limiting the impact of any leak.
77|key_exchange|What problem does key exchange solve?|Sharing a secret without a pre-shared secret|Before key exchange, two strangers could not share a secret without meeting or using an insecure courier; Diffie-Hellman solves this.
78|key_exchange|What is Diffie-Hellman based on?|The discrete logarithm problem|Its security rests on how hard it is to compute discrete logarithms in large prime groups: easy forward, infeasible backward.
79|key_exchange|What does the 'E' in ECDHE stand for?|Ephemeral|Ephemeral means a fresh, temporary key pair per session, which is what provides perfect forward secrecy.
80|key_exchange|Why do modern TLS implementations use ephemeral keys?|To provide perfect forward secrecy|Ephemeral (per-session) keys ensure that a leaked long-term key cannot decrypt past sessions.
'''

CRYPTO_QUIZ_BANK = tuple(
    CryptoQuestion(int(identifier), category, question, answer, explanation)
    for identifier, category, question, answer, explanation in (
        line.split("|") for line in _RAW_CRYPTO_BANK.splitlines() if line
    )
)

CRYPTO_CATEGORY_LABELS = {
    "Symmetric vs asymmetric": "symmetric_asymmetric",
    "Hashing": "hashing",
    "TLS and HTTPS": "tls_https",
    "Classic ciphers": "classic_ciphers",
    "Encoding vs encryption": "encoding",
    "Key security": "key_security",
    "Digital signatures": "digital_signatures",
    "Key exchange": "key_exchange",
}

# Plausible decoy answers for text-based crypto questions.
_CRYPTO_DECOY_POOL = (
    "AES", "RSA", "SHA-256", "TLS", "private key", "public key", "Caesar cipher",
    "Vigenere", "Base64", "DES", "MD5", "one-way", "key rotation", "salt",
    "rainbow table", "confidentiality", "integrity", "certificate", "encryption",
    "decryption", "password manager", "frequency analysis", "443", "two-factor authentication",
    "Diffie-Hellman", "digital signature", "session key", "non-repudiation",
    "perfect forward secrecy", "authenticity", "key pair", "certificate authority",
)


def crypto_choices(answer, rng=None):
    """Four distinct multiple-choice options for crypto quiz questions."""
    if answer.isdigit():
        value = int(answer)
        candidates = [answer, str(value + 1), str(max(0, value - 1)), str(value * 2)]
    else:
        candidates = [answer]
        for decoy in _CRYPTO_DECOY_POOL:
            if decoy != answer and len(candidates) < 4:
                candidates.append(decoy)
    values = list(dict.fromkeys(candidates))
    fill = 0
    while len(values) < 4:
        candidate = str(fill)
        if candidate not in values:
            values.append(candidate)
        fill += 1
    (rng or __import__("random")).shuffle(values)
    return values


def verify_crypto_quiz_bank() -> None:
    """Independently verify every answer that can be computed; check structure."""
    if len(CRYPTO_QUIZ_BANK) != 80 or {q.identifier for q in CRYPTO_QUIZ_BANK} != set(range(1, 81)):
        raise ValueError("Crypto quiz bank must contain identifiers 1 through 80.")
    from collections import Counter
    counts = Counter(q.category for q in CRYPTO_QUIZ_BANK)
    if any(count != 10 for count in counts.values()) or len(counts) != 8:
        raise ValueError("Crypto quiz bank must have 10 questions in each of 8 categories.")
    if any(not q.explanation for q in CRYPTO_QUIZ_BANK):
        raise ValueError("Every crypto question must carry a brief explanation.")
    computed = {
        1: "AES",
        2: "256",
        3: "RSA",
        11: "256",
        22: "443",
        31: caesar("CAT", 3),
        32: caesar("FDW", 3, decrypt=True),
        33: "13",
        35: "25",
    }
    for question in CRYPTO_QUIZ_BANK:
        if question.identifier in computed and question.correct_answer != computed[question.identifier]:
            raise ValueError(f"Crypto question {question.identifier} has an invalid answer.")


verify_crypto_quiz_bank()
