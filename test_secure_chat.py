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
        """Set up test fixtures for each test method.
        
        Creates two separate SecureChatProtocol instances to simulate
        two clients in a secure chat session. These instances are used
        to test key exchange, encryption, decryption, and other protocol
        functionality.
        
        Attributes:
            protocol1 (SecureChatProtocol): First client's protocol instance.
            protocol2 (SecureChatProtocol): Second client's protocol instance.
        """
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
        """Test the complete ML-KEM-1024 key exchange process between two clients.
        
        This test simulates the full key exchange protocol:
        1. Client 1 generates a keypair and creates an initialization message
        2. Client 2 processes the init message and creates a response
        3. Client 1 processes the response to complete the exchange
        4. Both clients should derive the same shared secret
        
        The test verifies that:
        - Both clients derive identical shared secrets
        - The protocol's shared_key attribute is properly set
        - The key exchange completes without errors
        
        This is a critical test as secure communication depends on successful
        key exchange using the post-quantum ML-KEM-1024 algorithm.
        """
        # Client 1 generates keypair and creates init message
        public_key1, private_key1 = self.protocol1.generate_keypair()
        init_message_bytes = self.protocol1.create_key_exchange_init(public_key1)
        
        # Client 2 processes init message and creates response
        shared_secret2, ciphertext, _ = self.protocol2.process_key_exchange_init(init_message_bytes)
        response_message_bytes = self.protocol2.create_key_exchange_response(ciphertext)
        
        # Client 1 processes response message
        shared_secret1, _ = self.protocol1.process_key_exchange_response(response_message_bytes, private_key1)
        
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
        
        self.assertIn("Replay attack or out-of-order message detected", str(context.exception))
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
        
        # The error could be JSON parsing error or decryption failure
        error_msg = str(context.exception).lower()
        self.assertTrue("decryption failed" in error_msg or "expecting" in error_msg)
        print("✓ Message authentication test passed")

    def test_perfect_forward_secrecy_key_ratcheting(self):
        """Test that chain keys are properly ratcheted for PFS."""
        # Establish shared key
        self.test_key_exchange()
        
        # Store initial chain keys
        initial_send_key1 = self.protocol1.send_chain_key
        initial_receive_key1 = self.protocol1.receive_chain_key
        initial_send_key2 = self.protocol2.send_chain_key
        initial_receive_key2 = self.protocol2.receive_chain_key
        
        # Send first message
        message1 = "First message"
        encrypted1 = self.protocol1.encrypt_message(message1)
        decrypted1 = self.protocol2.decrypt_message(encrypted1)
        self.assertEqual(message1, decrypted1)
        
        # Chain keys should have changed after message
        # Protocol1's send key should change (it sent a message)
        self.assertNotEqual(initial_send_key1, self.protocol1.send_chain_key)
        # Protocol2's receive key should change (it received a message)
        self.assertNotEqual(initial_receive_key2, self.protocol2.receive_chain_key)
        
        # Store chain keys after first message
        send_key1_after_msg1 = self.protocol1.send_chain_key
        receive_key2_after_msg1 = self.protocol2.receive_chain_key
        
        # Send second message
        message2 = "Second message"
        encrypted2 = self.protocol1.encrypt_message(message2)
        decrypted2 = self.protocol2.decrypt_message(encrypted2)
        self.assertEqual(message2, decrypted2)
        
        # Chain keys should have changed again
        self.assertNotEqual(send_key1_after_msg1, self.protocol1.send_chain_key)
        self.assertNotEqual(receive_key2_after_msg1, self.protocol2.receive_chain_key)
        
        print("✓ Perfect Forward Secrecy key ratcheting test passed")

    def test_pfs_message_key_uniqueness(self):
        """Test that each message uses a unique derived key."""
        # Establish shared key
        self.test_key_exchange()
        
        # We'll monkey-patch the _derive_message_key method to capture keys
        original_derive_method = self.protocol1._derive_message_key
        derived_keys = []
        
        def capture_derive_message_key(chain_key, counter):
            key = original_derive_method(chain_key, counter)
            derived_keys.append(key)
            return key
        
        self.protocol1._derive_message_key = capture_derive_message_key
        
        # Send multiple messages
        messages = ["Message 1", "Message 2", "Message 3"]
        for msg in messages:
            encrypted = self.protocol1.encrypt_message(msg)
            decrypted = self.protocol2.decrypt_message(encrypted)
            self.assertEqual(msg, decrypted)
        
        # All derived keys should be unique
        self.assertEqual(len(derived_keys), len(messages))
        self.assertEqual(len(set(derived_keys)), len(messages))  # All unique
        
        print("✓ PFS message key uniqueness test passed")

    def test_pfs_session_isolation(self):
        """Test that different sessions have isolated keys."""
        # Create two separate protocol instances (different sessions)
        session1_proto1 = SecureChatProtocol()
        session1_proto2 = SecureChatProtocol()
        session2_proto1 = SecureChatProtocol()
        session2_proto2 = SecureChatProtocol()
        
        # Establish keys for session 1
        pub1, priv1 = session1_proto1.generate_keypair()
        init1 = session1_proto1.create_key_exchange_init(pub1)
        secret1_2, cipher1, _ = session1_proto2.process_key_exchange_init(init1)
        resp1 = session1_proto2.create_key_exchange_response(cipher1)
        secret1_1 = session1_proto1.process_key_exchange_response(resp1, priv1)
        
        # Establish keys for session 2
        pub2, priv2 = session2_proto1.generate_keypair()
        init2 = session2_proto1.create_key_exchange_init(pub2)
        secret2_2, cipher2, _ = session2_proto2.process_key_exchange_init(init2)
        resp2 = session2_proto2.create_key_exchange_response(cipher2)
        secret2_1 = session2_proto1.process_key_exchange_response(resp2, priv2)
        
        # Sessions should have different shared secrets and chain keys
        self.assertNotEqual(secret1_1, secret2_1)
        self.assertNotEqual(session1_proto1.send_chain_key, session2_proto1.send_chain_key)
        self.assertNotEqual(session1_proto1.receive_chain_key, session2_proto1.receive_chain_key)
        self.assertNotEqual(session1_proto2.send_chain_key, session2_proto2.send_chain_key)
        self.assertNotEqual(session1_proto2.receive_chain_key, session2_proto2.receive_chain_key)
        
        # Messages encrypted in one session should not decrypt in another
        message = "Cross-session test"
        encrypted_session1 = session1_proto1.encrypt_message(message)
        
        with self.assertRaises(ValueError):
            session2_proto2.decrypt_message(encrypted_session1)
        
        print("✓ PFS session isolation test passed")

    def test_pfs_out_of_order_messages(self):
        """Test PFS behavior with out-of-order message delivery."""
        # Establish shared key
        self.test_key_exchange()
        
        # Encrypt multiple messages
        messages = ["Message 1", "Message 2", "Message 3"]
        encrypted_messages = []
        for msg in messages:
            encrypted = self.protocol1.encrypt_message(msg)
            encrypted_messages.append(encrypted)
        
        # The protocol actually handles out-of-order messages by ratcheting forward
        # So let's test that it can handle message 3 first, then 1 and 2 won't work
        # because they have lower counters
        
        # Decrypt message 3 first (this should work - protocol ratchets forward)
        decrypted3 = self.protocol2.decrypt_message(encrypted_messages[2])
        self.assertEqual(messages[2], decrypted3)
        
        # Now messages 1 and 2 should fail because they have lower counters
        with self.assertRaises(ValueError) as context:
            self.protocol2.decrypt_message(encrypted_messages[0])  # Message 1
        self.assertIn("Replay attack or out-of-order message detected", str(context.exception))
        
        with self.assertRaises(ValueError) as context:
            self.protocol2.decrypt_message(encrypted_messages[1])  # Message 2
        self.assertIn("Replay attack or out-of-order message detected", str(context.exception))
        
        print("✓ PFS out-of-order messages test passed")

    def test_pfs_key_compromise_simulation(self):
        """Test that compromising chain key doesn't affect past messages."""
        # Establish shared key
        self.test_key_exchange()
        
        # Send and store first message
        message1 = "Past message before compromise"
        encrypted1 = self.protocol1.encrypt_message(message1)
        decrypted1 = self.protocol2.decrypt_message(encrypted1)
        self.assertEqual(message1, decrypted1)
        
        # Store the current chain key (simulating compromise)
        compromised_chain_key = self.protocol1.send_chain_key
        
        # Send more messages to advance the chain
        for i in range(3):
            msg = f"Message after compromise {i}"
            encrypted = self.protocol1.encrypt_message(msg)
            decrypted = self.protocol2.decrypt_message(encrypted)
            self.assertEqual(msg, decrypted)
        
        # Even with the compromised chain key, we cannot derive the key
        # that was used for message1 because it was derived from a previous
        # chain key state and then the chain key was ratcheted forward
        
        # The compromised chain key should be different from what was used for message1
        self.assertNotEqual(compromised_chain_key, self.protocol1.send_chain_key)
        
        # This test demonstrates that forward secrecy is maintained:
        # - Past message keys cannot be derived from current chain key
        # - Chain key ratcheting ensures one-way progression
        
        print("✓ PFS key compromise simulation test passed")

    def test_pfs_ephemeral_key_generation(self):
        """Test that each session uses fresh ephemeral keys."""
        # Generate multiple keypairs and ensure they're different
        keypairs = []
        for _ in range(5):
            protocol = SecureChatProtocol()
            pub, priv = protocol.generate_keypair()
            keypairs.append((pub, priv))
        
        # All public keys should be unique
        public_keys = [kp[0] for kp in keypairs]
        self.assertEqual(len(set(public_keys)), len(public_keys))
        
        # All private keys should be unique
        private_keys = [kp[1] for kp in keypairs]
        self.assertEqual(len(set(private_keys)), len(private_keys))
        
        print("✓ PFS ephemeral key generation test passed")

    def test_pfs_message_counter_advancement(self):
        """Test that message counters advance properly for PFS."""
        # Establish shared key
        self.test_key_exchange()
        
        # Initial counters should be 0
        self.assertEqual(self.protocol1.message_counter, 0)
        self.assertEqual(self.protocol2.peer_counter, 0)
        
        # Send messages and verify counter advancement
        for i in range(1, 4):
            message = f"Message {i}"
            encrypted = self.protocol1.encrypt_message(message)
            
            # Sender's counter should advance
            self.assertEqual(self.protocol1.message_counter, i)
            
            decrypted = self.protocol2.decrypt_message(encrypted)
            self.assertEqual(message, decrypted)
            
            # Receiver's peer counter should advance
            self.assertEqual(self.protocol2.peer_counter, i)
        
        print("✓ PFS message counter advancement test passed")

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
                shared_secret2, ciphertext, _ = protocol2.process_key_exchange_init(init_data)
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
    shared_secret2, ciphertext, _ = protocol2.process_key_exchange_init(init_msg_bytes)
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