# test_secure_chat.py - Test script for secure chat application
import unittest
import threading
import time
import socket
from shared import SecureChatProtocol
from server import SecureChatServer

class TestSecureChatProtocol(unittest.TestCase):
    """Test the secure chat protocol functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.protocol1 = SecureChatProtocol()
        self.protocol2 = SecureChatProtocol()
    
    def test_key_generation(self):
        """Test ML-KEM key pair generation."""
        public_key, private_key = self.protocol1.generate_keypair()
        
        # Check that keys are generated and have expected lengths
        self.assertIsInstance(public_key, bytes)
        self.assertIsInstance(private_key, bytes)
        self.assertGreater(len(public_key), 0)
        self.assertGreater(len(private_key), 0)
        print("✓ Key generation test passed")
    
    def test_key_exchange(self):
        """Test the complete key exchange process."""
        # Client 1 generates keypair and creates init message
        public_key1, private_key1 = self.protocol1.generate_keypair()
        init_message_bytes = self.protocol1.create_key_exchange_init(public_key1)
        
        # Client 2 processes init message and creates response
        shared_secret2, ciphertext = self.protocol2.process_key_exchange_init(init_message_bytes)
        response_message_bytes = self.protocol2.create_key_exchange_response(ciphertext)
        
        # Client 1 processes response message
        shared_secret1 = self.protocol1.process_key_exchange_response(response_message_bytes, private_key1)
        
        # Both clients should have the same shared secret
        self.assertEqual(shared_secret1, shared_secret2)
        self.assertEqual(self.protocol1.shared_key, self.protocol2.shared_key)
        print("✓ Key exchange test passed")
    
    def test_message_encryption_decryption(self):
        """Test message encryption and decryption."""
        # First establish shared key
        self.test_key_exchange()
        
        # Test message encryption/decryption
        original_message = "Hello, this is a secret message!"
        
        # Encrypt with protocol1
        encrypted_data = self.protocol1.encrypt_message(original_message)
        
        # Decrypt with protocol2
        decrypted_message = self.protocol2.decrypt_message(encrypted_data)
        
        self.assertEqual(original_message, decrypted_message)
        print("✓ Message encryption/decryption test passed")
    
    def test_replay_protection(self):
        """Test replay attack protection."""
        # Establish shared key
        self.test_key_exchange()
        
        # Encrypt a message
        message = "Test message"
        encrypted_data = self.protocol1.encrypt_message(message)
        
        # First decryption should work
        decrypted1 = self.protocol2.decrypt_message(encrypted_data)
        self.assertEqual(message, decrypted1)
        
        # Second decryption of same message should fail (replay protection)
        with self.assertRaises(ValueError) as context:
            self.protocol2.decrypt_message(encrypted_data)
        
        self.assertIn("Replay attack detected", str(context.exception))
        print("✓ Replay protection test passed")
    
    def test_message_authentication(self):
        """Test message authentication (AES-GCM verification)."""
        # Establish shared key
        self.test_key_exchange()
        
        # Encrypt a message
        message = "Authenticated message"
        encrypted_data = self.protocol1.encrypt_message(message)
        
        # Tamper with the message (modify one byte)
        tampered_data = bytearray(encrypted_data)
        tampered_data[10] = (tampered_data[10] + 1) % 256
        tampered_data = bytes(tampered_data)
        
        # Decryption should fail due to authentication failure
        with self.assertRaises(ValueError) as context:
            self.protocol2.decrypt_message(tampered_data)
        
        self.assertIn("decryption failed", str(context.exception).lower())
        print("✓ Message authentication test passed")

class TestSecureChatIntegration(unittest.TestCase):
    """Integration tests for the complete secure chat system."""
    
    def setUp(self):
        """Set up test server."""
        self.server = None
        self.server_thread = None
        self.clients = []
    
    def tearDown(self):
        """Clean up test resources."""
        # Close client connections
        for client in self.clients:
            try:
                client.close()
            except:
                pass
        
        # Stop server
        if self.server:
            self.server.stop()
        
        if self.server_thread:
            self.server_thread.join(timeout=2)
    
    def start_test_server(self):
        """Start a test server in a separate thread."""
        self.server = SecureChatServer('localhost', 9999)
        self.server_thread = threading.Thread(target=self.server.start)
        self.server_thread.daemon = True
        self.server_thread.start()
        time.sleep(0.5)  # Give server time to start
    
    def create_test_client(self):
        """Create a test client connection."""
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('localhost', 9999))
        self.clients.append(client)
        return client
    
    def test_server_client_connection(self):
        """Test basic server-client connection."""
        self.start_test_server()
        
        # Connect first client
        client1 = self.create_test_client()
        time.sleep(0.1)
        
        # Connect second client
        client2 = self.create_test_client()
        time.sleep(0.1)
        
        # Both clients should be connected
        self.assertEqual(len(self.server.clients), 2)
        print("✓ Server-client connection test passed")
    
    def test_key_exchange_through_server(self):
        """Test key exchange through server routing."""
        self.start_test_server()
        
        # Connect two clients
        client1 = self.create_test_client()
        client2 = self.create_test_client()
        time.sleep(0.5)  # Wait for server to initiate key exchange
        
        # Simulate client behavior - receive initiate message and perform key exchange
        from shared import SecureChatProtocol, send_message, receive_message
        import json
        
        # Client 1 should receive initiate message and start key exchange
        try:
            # Receive initiate message
            initiate_data = receive_message(client1)
            initiate_msg = json.loads(initiate_data.decode('utf-8'))
            
            if initiate_msg.get("type") == "initiate_key_exchange":
                # Client 1 generates keypair and sends init message
                protocol1 = SecureChatProtocol()
                public_key1, private_key1 = protocol1.generate_keypair()
                init_message = protocol1.create_key_exchange_init(public_key1)
                send_message(client1, init_message)
                
                # Client 2 should receive the init message and respond
                init_data = receive_message(client2)
                protocol2 = SecureChatProtocol()
                shared_secret2, ciphertext = protocol2.process_key_exchange_init(init_data)
                response_message = protocol2.create_key_exchange_response(ciphertext)
                send_message(client2, response_message)
                
                # Client 1 should receive the response and complete key exchange
                response_data = receive_message(client1)
                shared_secret1 = protocol1.process_key_exchange_response(response_data, private_key1)
                
                # Both should have the same shared secret
                self.assertEqual(shared_secret1, shared_secret2)
                
        except Exception as e:
            print(f"Key exchange simulation failed: {e}")
        
        # Give some time for server to process the key exchange completion
        time.sleep(1.0)
        
        # Check that both clients have completed key exchange
        client_handlers = list(self.server.clients.values())
        
        # Verify key exchange completed
        for handler in client_handlers:
            self.assertTrue(handler.key_exchange_complete, "Key exchange should be complete")
        
        print("✓ Key exchange through server test passed")

def run_manual_test():
    """Run a manual test to demonstrate the secure chat functionality."""
    print("\n" + "="*50)
    print("MANUAL TEST: Secure Chat Demonstration")
    print("="*50)
    
    print("\n1. Testing basic cryptographic functions...")
    
    # Test basic encryption
    protocol1 = SecureChatProtocol()
    protocol2 = SecureChatProtocol()
    
    # Simulate key exchange
    public_key, private_key = protocol1.generate_keypair()
    init_msg_bytes = protocol1.create_key_exchange_init(public_key)
    shared_secret2, ciphertext = protocol2.process_key_exchange_init(init_msg_bytes)
    response_msg_bytes = protocol2.create_key_exchange_response(ciphertext)
    shared_secret1 = protocol1.process_key_exchange_response(response_msg_bytes, private_key)
    
    print(f"   Shared secrets match: {shared_secret1 == shared_secret2}")
    
    # Test message encryption
    test_message = "This is a secure test message! 🔒"
    encrypted = protocol1.encrypt_message(test_message)
    decrypted = protocol2.decrypt_message(encrypted)
    
    print(f"   Original message: {test_message}")
    print(f"   Decrypted message: {decrypted}")
    print(f"   Messages match: {test_message == decrypted}")
    

if __name__ == "__main__":
    print("Secure Chat Test Suite")
    print("=====================")
    
    # Run unit tests
    print("\nRunning unit tests...")
    unittest.main(argv=[''], exit=False, verbosity=0)
    
    # Run manual demonstration
    run_manual_test()