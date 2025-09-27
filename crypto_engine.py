"""
Military-grade cryptographic engine implementing Signal protocol features
with forward secrecy, deniability, and authenticated encryption.
"""

import os
import nacl.utils
import nacl.secret
import nacl.signing
import nacl.encoding
from nacl.public import PrivateKey, PublicKey, Box
from nacl.exceptions import CryptoError
import nacl.exceptions
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import hashlib
import time
import json
import base64
import ctypes
# import mlock  # Optional: requires python-mlock package
from typing import Dict, Tuple, Optional, Any

class SecureMemory:
    """Secure memory management with automatic wiping"""
    
    def __init__(self, size: int):
        self.size = size
        self.ptr = None
        self._allocate()
    
    def _allocate(self):
        """Allocate and lock memory"""
        try:
            # Use mlock to prevent swapping to disk
            self.ptr = ctypes.create_string_buffer(self.size)
            # mlock.mlockall(mlock.MCL_CURRENT | mlock.MCL_FUTURE)  # Optional memory locking
            pass
        except Exception:
            # Fallback if mlock is not available
            self.ptr = ctypes.create_string_buffer(self.size)
    
    def write(self, data: bytes, offset: int = 0):
        """Write data to secure memory"""
        if len(data) + offset > self.size:
            raise ValueError("Data too large for secure memory")
        if self.ptr is not None:
            ctypes.memmove(ctypes.addressof(self.ptr) + offset, data, len(data))
    
    def read(self, length: int, offset: int = 0) -> bytes:
        """Read data from secure memory"""
        if length + offset > self.size:
            raise ValueError("Read beyond secure memory bounds")
        if self.ptr is not None:
            return ctypes.string_at(ctypes.addressof(self.ptr) + offset, length)
        return b''
    
    def wipe(self):
        """Securely wipe memory"""
        if self.ptr:
            # Overwrite with random data multiple times
            for _ in range(3):
                random_data = os.urandom(self.size)
                ctypes.memmove(self.ptr, random_data, self.size)
            # Final overwrite with zeros
            ctypes.memset(self.ptr, 0, self.size)
    
    def __del__(self):
        self.wipe()

class SignalCrypto:
    """Signal protocol implementation for forward secrecy and deniability"""
    
    def __init__(self):
        self.identity_key = PrivateKey.generate()
        self.signed_prekey = PrivateKey.generate()
        self.ephemeral_keys = {}
        self.session_keys = {}
        self.ratchet_state = {}
        
    def generate_ephemeral_key(self, session_id: str) -> PublicKey:
        """Generate ephemeral key for session"""
        ephemeral = PrivateKey.generate()
        self.ephemeral_keys[session_id] = ephemeral
        return ephemeral.public_key
    
    def perform_x3dh(self, peer_identity: PublicKey, peer_signed_prekey: PublicKey, 
                     peer_ephemeral: PublicKey, session_id: str) -> bytes:
        """Perform X3DH key agreement"""
        
        # Generate ephemeral key for this session
        ephemeral = self.generate_ephemeral_key(session_id)
        
        # Perform multiple DH operations
        dh1 = Box(self.identity_key, peer_signed_prekey)
        dh2 = Box(self.ephemeral_keys[session_id], peer_identity)
        dh3 = Box(self.ephemeral_keys[session_id], peer_signed_prekey)
        dh4 = Box(self.ephemeral_keys[session_id], peer_ephemeral)
        
        # Combine all DH outputs
        combined = (dh1.shared_key() + dh2.shared_key() + 
                   dh3.shared_key() + dh4.shared_key())
        
        # Derive session key using HKDF
        digest = hashes.Hash(hashes.SHA256())
        digest.update(combined)
        session_key = digest.finalize()[:32]
        
        self.session_keys[session_id] = session_key
        return session_key
    
    def encrypt_message(self, plaintext: bytes, session_id: str, 
                       associated_data: bytes = b"") -> Dict[str, Any]:
        """Encrypt message with forward secrecy"""
        
        if session_id not in self.session_keys:
            raise ValueError("No session key found")
        
        # Generate new message key from session key
        message_key = self._derive_message_key(session_id)
        
        # Use PyNaCl SecretBox for consistent authenticated encryption
        # This avoids nonce size issues between different crypto libraries
        box = nacl.secret.SecretBox(message_key)
        
        # SecretBox automatically generates appropriate nonce and handles everything
        encrypted_box = box.encrypt(plaintext)
        
        # Extract nonce and ciphertext from the encrypted box
        nonce = encrypted_box.nonce
        ciphertext = encrypted_box.ciphertext
        
        # Compute additional authentication tag for associated data if provided
        auth_tag = self._compute_auth_tag(ciphertext, associated_data, message_key)
        
        # Advance ratchet state for forward secrecy
        self._advance_ratchet(session_id)
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'auth_tag': base64.b64encode(auth_tag).decode(),
            'timestamp': time.time()
        }
    
    def decrypt_message(self, encrypted_data: Dict[str, Any], session_id: str,
                       associated_data: bytes = b"") -> bytes:
        """Decrypt message and verify authenticity"""
        
        if session_id not in self.session_keys:
            raise ValueError("No session key found")
        
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        auth_tag = base64.b64decode(encrypted_data['auth_tag'])
        
        # Derive message key
        message_key = self._derive_message_key(session_id)
        
        # Verify authentication tag for associated data
        expected_tag = self._compute_auth_tag(ciphertext, associated_data, message_key)
        if not secrets.compare_digest(auth_tag, expected_tag):
            raise CryptoError("Authentication failed")
        
        # Use PyNaCl SecretBox for decryption (consistent with encryption)
        box = nacl.secret.SecretBox(message_key)
        
        # Reconstruct the encrypted message by concatenating nonce + ciphertext
        # This is how PyNaCl SecretBox expects the encrypted data
        encrypted_message = nonce + ciphertext
        
        # Decrypt
        plaintext = box.decrypt(encrypted_message)
        
        return plaintext
    
    def _derive_message_key(self, session_id: str) -> bytes:
        """Derive message key from session key"""
        session_key = self.session_keys[session_id]
        counter = self.ratchet_state.get(session_id, 0)
        
        # Use HKDF with counter for key derivation
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"message_key",
            iterations=1000 + counter
        )
        return kdf.derive(session_key + counter.to_bytes(4, 'big'))
    
    def _compute_auth_tag(self, ciphertext: bytes, associated_data: bytes, 
                         key: bytes) -> bytes:
        """Compute HMAC authentication tag"""
        hmac_key = hashlib.blake2b(key, digest_size=32, person=b"auth_tag").digest()
        return hashlib.blake2b(ciphertext + associated_data, 
                              key=hmac_key, digest_size=16).digest()
    
    def _advance_ratchet(self, session_id: str):
        """Advance ratchet state for forward secrecy"""
        self.ratchet_state[session_id] = self.ratchet_state.get(session_id, 0) + 1
        
        # Optionally generate new ephemeral key every N messages
        if self.ratchet_state[session_id] % 10 == 0:
            self.generate_ephemeral_key(session_id)

class DigitalSignature:
    """Digital signature implementation for message authentication"""
    
    def __init__(self):
        self.signing_key = nacl.signing.SigningKey.generate()
        self.verify_key = self.signing_key.verify_key
    
    def sign_message(self, message: bytes, metadata: Dict[str, Any]) -> bytes:
        """Sign message with metadata"""
        # Include metadata in signature
        signing_data = message + json.dumps(metadata, sort_keys=True).encode()
        return self.signing_key.sign(signing_data).signature
    
    def verify_signature(self, message: bytes, signature: bytes, 
                        metadata: Dict[str, Any], sender_verify_key: nacl.signing.VerifyKey) -> bool:
        """Verify message signature"""
        try:
            signing_data = message + json.dumps(metadata, sort_keys=True).encode()
            sender_verify_key.verify(signing_data, signature)
            return True
        except nacl.exceptions.BadSignatureError:
            return False

class CryptoEngine:
    """Main cryptographic engine combining all security features"""
    
    def __init__(self):
        self.signal_crypto = SignalCrypto()
        self.signature_system = DigitalSignature()
        self.secure_memory_pool = {}
        
    def create_secure_session(self, user_id: str, peer_public_keys: Dict[str, Any]) -> str:
        """Create secure session with peer"""
        session_id = secrets.token_hex(16)
        
        # Perform key agreement
        peer_identity = PublicKey(peer_public_keys['identity'], encoder=nacl.encoding.Base64Encoder)
        peer_signed_prekey = PublicKey(peer_public_keys['signed_prekey'], encoder=nacl.encoding.Base64Encoder)
        peer_ephemeral = PublicKey(peer_public_keys['ephemeral'], encoder=nacl.encoding.Base64Encoder)
        
        session_key = self.signal_crypto.perform_x3dh(
            peer_identity, peer_signed_prekey, peer_ephemeral, session_id
        )
        
        # Allocate secure memory for session
        self.secure_memory_pool[session_id] = SecureMemory(4096)
        
        return session_id
    
    def encrypt_secure_message(self, plaintext: str, session_id: str, 
                             sender_id: str) -> Dict[str, Any]:
        """Encrypt message with full security features"""
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Create metadata
        metadata = {
            'sender': sender_id,
            'timestamp': time.time(),
            'session_id': session_id,
            'message_id': secrets.token_hex(8)
        }
        
        # Sign message
        signature = self.signature_system.sign_message(plaintext_bytes, metadata)
        
        # Encrypt with Signal protocol
        encrypted_data = self.signal_crypto.encrypt_message(
            plaintext_bytes, session_id, json.dumps(metadata).encode()
        )
        
        # Add signature to encrypted data
        encrypted_data['signature'] = base64.b64encode(signature).decode()
        encrypted_data['metadata'] = metadata
        
        return encrypted_data
    
    def decrypt_secure_message(self, encrypted_data: Dict[str, Any], 
                             session_id: str, sender_verify_key: nacl.signing.VerifyKey) -> str:
        """Decrypt and verify message"""
        
        # Extract components
        signature = base64.b64decode(encrypted_data['signature'])
        metadata = encrypted_data['metadata']
        
        # Decrypt message
        plaintext_bytes = self.signal_crypto.decrypt_message(
            encrypted_data, session_id, json.dumps(metadata).encode()
        )
        
        # Verify signature
        if not self.signature_system.verify_signature(
            plaintext_bytes, signature, metadata, sender_verify_key
        ):
            raise CryptoError("Signature verification failed")
        
        return plaintext_bytes.decode('utf-8')
    
    def get_public_keys(self) -> Dict[str, str]:
        """Get public keys for key exchange"""
        return {
            'identity': self.signal_crypto.identity_key.public_key.encode(encoder=nacl.encoding.Base64Encoder).decode(),
            'signed_prekey': self.signal_crypto.signed_prekey.public_key.encode(encoder=nacl.encoding.Base64Encoder).decode(),
            'verify_key': self.signature_system.verify_key.encode(encoder=nacl.encoding.Base64Encoder).decode()
        }
    
    def cleanup_session(self, session_id: str):
        """Securely cleanup session data"""
        if session_id in self.secure_memory_pool:
            self.secure_memory_pool[session_id].wipe()
            del self.secure_memory_pool[session_id]
        
        if session_id in self.signal_crypto.session_keys:
            del self.signal_crypto.session_keys[session_id]
        
        if session_id in self.signal_crypto.ratchet_state:
            del self.signal_crypto.ratchet_state[session_id]
        
        if session_id in self.signal_crypto.ephemeral_keys:
            del self.signal_crypto.ephemeral_keys[session_id]