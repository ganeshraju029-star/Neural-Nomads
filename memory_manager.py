"""
Military-grade memory management with secure wiping and tamper-proof storage
"""

import os
import gc
import ctypes
import secrets
import time
import threading
import psutil
from typing import Dict, Any, Optional, Callable, List
import weakref
import json
import hashlib

class SecureMemoryBlock:
    """Individual secure memory block with automatic wiping"""
    
    def __init__(self, size: int):
        self.size = size
        self.data = bytearray(size)
        self.is_locked = False
        self.access_count = 0
        self.created_at = time.time()
        self.last_access = time.time()
        self._lock = threading.Lock()
        
    def write(self, data: bytes, offset: int = 0) -> bool:
        """Write data to secure memory block"""
        with self._lock:
            if len(data) + offset > self.size:
                return False
                
            self.data[offset:offset + len(data)] = data
            self.last_access = time.time()
            self.access_count += 1
            return True
    
    def read(self, length: int, offset: int = 0) -> Optional[bytes]:
        """Read data from secure memory block"""
        with self._lock:
            if length + offset > self.size:
                return None
                
            self.last_access = time.time()
            self.access_count += 1
            return bytes(self.data[offset:offset + length])
    
    def wipe(self):
        """Securely wipe memory block"""
        with self._lock:
            if self.data and len(self.data) > 0:
                # Multiple pass wiping
                for pattern in [b'\x00', b'\xFF', b'\xAA', b'\x55']:
                    for i in range(len(self.data)):
                        self.data[i] = pattern[0]
                
                # Final random pass
                random_data = os.urandom(len(self.data))
                for i in range(len(self.data)):
                    self.data[i] = random_data[i]
                
                # Clear the array
                self.data = bytearray(0)
    
    def __del__(self):
        self.wipe()

class MemoryPool:
    """Pool of secure memory blocks for efficient allocation"""
    
    def __init__(self, block_size: int = 4096, initial_blocks: int = 10):
        self.block_size = block_size
        self.available_blocks: List[SecureMemoryBlock] = []
        self.allocated_blocks: Dict[str, SecureMemoryBlock] = {}
        self._lock = threading.Lock()
        
        # Pre-allocate blocks
        for _ in range(initial_blocks):
            self.available_blocks.append(SecureMemoryBlock(block_size))
    
    def allocate(self, size: int) -> Optional[str]:
        """Allocate memory block and return handle"""
        if size > self.block_size:
            return None
            
        with self._lock:
            if not self.available_blocks:
                # Create new block if needed
                self.available_blocks.append(SecureMemoryBlock(self.block_size))
            
            block = self.available_blocks.pop()
            handle = secrets.token_hex(16)
            self.allocated_blocks[handle] = block
            return handle
    
    def deallocate(self, handle: str):
        """Deallocate memory block"""
        with self._lock:
            if handle in self.allocated_blocks:
                block = self.allocated_blocks[handle]
                block.wipe()
                del self.allocated_blocks[handle]
                # Don't reuse blocks for security
    
    def get_block(self, handle: str) -> Optional[SecureMemoryBlock]:
        """Get memory block by handle"""
        return self.allocated_blocks.get(handle)
    
    def cleanup_expired(self, max_age: int = 3600):
        """Clean up old allocated blocks"""
        current_time = time.time()
        expired_handles = []
        
        with self._lock:
            for handle, block in self.allocated_blocks.items():
                if current_time - block.last_access > max_age:
                    expired_handles.append(handle)
        
        for handle in expired_handles:
            self.deallocate(handle)

class MessageStorage:
    """In-memory only message storage with automatic destruction"""
    
    def __init__(self, memory_pool: MemoryPool):
        self.memory_pool = memory_pool
        self.messages: Dict[str, Dict[str, Any]] = {}
        self.message_timers: Dict[str, threading.Timer] = {}
        self.access_log: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
        
    def store_message(self, message_id: str, encrypted_data: Dict[str, Any], 
                     ttl_seconds: int = 300) -> bool:
        """Store encrypted message in memory"""
        
        # Serialize message data
        message_json = json.dumps(encrypted_data).encode('utf-8')
        
        # Allocate secure memory
        memory_handle = self.memory_pool.allocate(len(message_json) + 100)
        if not memory_handle:
            return False
        
        # Store in secure memory
        block = self.memory_pool.get_block(memory_handle)
        if not block or not block.write(message_json):
            self.memory_pool.deallocate(memory_handle)
            return False
        
        with self._lock:
            # Store message metadata
            self.messages[message_id] = {
                'memory_handle': memory_handle,
                'size': len(message_json),
                'created_at': time.time(),
                'access_count': 0,
                'max_access': 1,  # Self-destruct after one read
                'ttl_seconds': ttl_seconds,
                'checksum': hashlib.sha256(message_json).hexdigest()
            }
            
            # Set destruction timer
            timer = threading.Timer(ttl_seconds, self._destroy_message, args=[message_id])
            timer.start()
            self.message_timers[message_id] = timer
            
            # Initialize access log
            self.access_log[message_id] = [time.time()]
        
        return True
    
    def retrieve_message(self, message_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve and optionally destroy message"""
        
        with self._lock:
            if message_id not in self.messages:
                return None
            
            message_meta = self.messages[message_id]
            
            # Check access limit
            if message_meta['access_count'] >= message_meta['max_access']:
                self._destroy_message(message_id)
                return None
            
            # Get message data from secure memory
            memory_handle = message_meta['memory_handle']
            block = self.memory_pool.get_block(memory_handle)
            
            if not block:
                self._destroy_message(message_id)
                return None
            
            # Read data
            message_data = block.read(message_meta['size'])
            if not message_data:
                self._destroy_message(message_id)
                return None
            
            # Verify integrity
            checksum = hashlib.sha256(message_data).hexdigest()
            if checksum != message_meta['checksum']:
                # Tampering detected - destroy immediately
                self._destroy_message(message_id)
                return None
            
            # Update access tracking
            message_meta['access_count'] += 1
            self.access_log[message_id].append(time.time())
            
            # Self-destruct after access
            self._destroy_message(message_id)
            
            # Parse and return data
            try:
                return json.loads(message_data.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None
    
    def _destroy_message(self, message_id: str):
        """Internal method to destroy message"""
        if message_id not in self.messages:
            return
        
        message_meta = self.messages[message_id]
        
        # Deallocate secure memory
        self.memory_pool.deallocate(message_meta['memory_handle'])
        
        # Cancel timer
        if message_id in self.message_timers:
            self.message_timers[message_id].cancel()
            del self.message_timers[message_id]
        
        # Clear metadata
        del self.messages[message_id]
        
        # Clear access log
        if message_id in self.access_log:
            del self.access_log[message_id]
    
    def destroy_message(self, message_id: str) -> bool:
        """Manually destroy message"""
        with self._lock:
            if message_id in self.messages:
                self._destroy_message(message_id)
                return True
            return False
    
    def list_messages(self) -> List[Dict[str, Any]]:
        """List active messages (metadata only)"""
        with self._lock:
            return [
                {
                    'message_id': msg_id,
                    'created_at': meta['created_at'],
                    'access_count': meta['access_count'],
                    'ttl_remaining': max(0, meta['ttl_seconds'] - (time.time() - meta['created_at']))
                }
                for msg_id, meta in self.messages.items()
            ]

class AntiForensics:
    """Anti-forensics measures to prevent data recovery"""
    
    @staticmethod
    def secure_delete_memory():
        """Trigger garbage collection and memory overwriting"""
        # Force garbage collection
        for _ in range(3):
            gc.collect()
        
        # Try to clear Python string intern table (limited effectiveness)
        try:
            # Create dummy strings to potentially overwrite memory
            dummy_data = [os.urandom(1024) for _ in range(100)]
            del dummy_data
        except Exception:
            pass
    
    @staticmethod
    def detect_memory_forensics() -> bool:
        """Detect potential memory forensics tools"""
        try:
            # Check for suspicious processes
            suspicious_processes = [
                'volatility', 'rekall', 'memdump', 'winpmem', 
                'linpmem', 'fmem', 'dumpit', 'memoryze'
            ]
            
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    proc_name = proc.info['name'].lower()
                    if any(sus in proc_name for sus in suspicious_processes):
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            return False
        except Exception:
            return False
    
    @staticmethod
    def clear_swap_space():
        """Attempt to clear swap space (Unix systems)"""
        try:
            os.system('sudo swapoff -a && sudo swapon -a')
        except Exception:
            pass
    
    @staticmethod
    def obfuscate_memory_patterns():
        """Create noise in memory to obfuscate real data"""
        noise_data = []
        for _ in range(50):
            # Create random data that looks like encrypted messages
            fake_data = {
                'ciphertext': os.urandom(256).hex(),
                'nonce': os.urandom(12).hex(),
                'timestamp': time.time() + secrets.randbelow(86400)
            }
            noise_data.append(json.dumps(fake_data))
        
        # Keep in memory briefly then clear
        time.sleep(0.1)
        for i in range(len(noise_data)):
            noise_data[i] = os.urandom(len(noise_data[i]))
        del noise_data

class SecureMemoryManager:
    """Main memory manager with military-grade security features"""
    
    def __init__(self):
        self.memory_pool = MemoryPool(block_size=8192, initial_blocks=20)
        self.message_storage = MessageStorage(self.memory_pool)
        self.anti_forensics = AntiForensics()
        self.monitoring_enabled = True
        self.access_monitor = AccessMonitor()
        
        # Start background cleanup
        self._start_cleanup_thread()
        
        # Start anti-forensics monitoring
        self._start_anti_forensics_monitoring()
    
    def store_secure_message(self, message_id: str, encrypted_data: Dict[str, Any],
                           ttl_seconds: int = 300, max_access: int = 1) -> bool:
        """Store message with advanced security features"""
        
        # Check for forensics tools
        if self.anti_forensics.detect_memory_forensics():
            # Under forensics attack - don't store
            return False
        
        # Obfuscate memory patterns
        self.anti_forensics.obfuscate_memory_patterns()
        
        # Store message
        success = self.message_storage.store_message(message_id, encrypted_data, ttl_seconds)
        
        if success:
            # Log access
            self.access_monitor.log_store(message_id, time.time())
        
        return success
    
    def retrieve_secure_message(self, message_id: str, requester_info: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """Retrieve message with security monitoring"""
        
        # Log access attempt
        self.access_monitor.log_access_attempt(message_id, requester_info or {})
        
        # Check for suspicious access patterns
        if self.access_monitor.detect_suspicious_access(message_id):
            # Suspicious access detected - destroy message
            self.message_storage.destroy_message(message_id)
            return None
        
        # Retrieve message
        message = self.message_storage.retrieve_message(message_id)
        
        if message:
            self.access_monitor.log_successful_access(message_id)
        
        return message
    
    def emergency_wipe(self):
        """Emergency wipe of all sensitive data"""
        # Clear all messages
        for message_id in list(self.message_storage.messages.keys()):
            self.message_storage.destroy_message(message_id)
        
        # Clear memory pool
        for handle in list(self.memory_pool.allocated_blocks.keys()):
            self.memory_pool.deallocate(handle)
        
        # Clear available blocks
        for block in self.memory_pool.available_blocks:
            block.wipe()
        self.memory_pool.available_blocks.clear()
        
        # Anti-forensics measures
        self.anti_forensics.secure_delete_memory()
        self.anti_forensics.obfuscate_memory_patterns()
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread"""
        def cleanup_loop():
            while self.monitoring_enabled:
                try:
                    self.memory_pool.cleanup_expired()
                    self.anti_forensics.secure_delete_memory()
                    time.sleep(60)  # Cleanup every minute
                except Exception:
                    pass
        
        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()
    
    def _start_anti_forensics_monitoring(self):
        """Start anti-forensics monitoring"""
        def monitor_loop():
            while self.monitoring_enabled:
                try:
                    if self.anti_forensics.detect_memory_forensics():
                        # Emergency wipe on forensics detection
                        self.emergency_wipe()
                        break
                    time.sleep(30)  # Check every 30 seconds
                except Exception:
                    pass
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()

class AccessMonitor:
    """Monitor access patterns for security threats"""
    
    def __init__(self):
        self.access_log: Dict[str, List[Dict[str, Any]]] = {}
        self.suspicious_patterns = set()
        
    def log_store(self, message_id: str, timestamp: float):
        """Log message storage"""
        if message_id not in self.access_log:
            self.access_log[message_id] = []
        
        self.access_log[message_id].append({
            'action': 'store',
            'timestamp': timestamp
        })
    
    def log_access_attempt(self, message_id: str, requester_info: Dict[str, Any]):
        """Log access attempt"""
        if message_id not in self.access_log:
            self.access_log[message_id] = []
        
        self.access_log[message_id].append({
            'action': 'access_attempt',
            'timestamp': time.time(),
            'requester': requester_info
        })
    
    def log_successful_access(self, message_id: str):
        """Log successful access"""
        if message_id not in self.access_log:
            self.access_log[message_id] = []
        
        self.access_log[message_id].append({
            'action': 'successful_access',
            'timestamp': time.time()
        })
    
    def detect_suspicious_access(self, message_id: str) -> bool:
        """Detect suspicious access patterns"""
        if message_id not in self.access_log:
            return False
        
        log_entries = self.access_log[message_id]
        current_time = time.time()
        
        # Check for rapid repeated access
        recent_attempts = [
            entry for entry in log_entries 
            if current_time - entry['timestamp'] < 60  # Last minute
        ]
        
        if len(recent_attempts) > 5:  # More than 5 attempts in a minute
            return True
        
        return False