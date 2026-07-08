WORK IN PROGRESS

Messages are json, encoded as utf-8 strings.
every message has "type": int
every message has "nonce": string (unpadded base64)

On program start:
Generate SLH-DSA SHA-256 keypair (KEX signing key)
Generate Ed25519 keypair (KEX signing key)

Generate X25519 keypair (Root key)
Generate 512 bit random client random

On connect to server:
Server sends:
{
    "type": 0,
    "version": ["X.Y.Z"],
    "server-identifier": [server_identifier],
}

Key Exchange:
every message has "ed25519-sig": string (unpadded base64)
every message has "slh-sig": string (unpadded base64)

The signatures are applied ed25519, then slh-dsa, so slh-dsa signs the message itself and the ed25519 signature.

Server chooses client A, then sends KEX_START (10) message to client A.
Client A sends:
{
    "type": 11, (KEX_INIT)
    "version": ["X.Y.Z"],
    "client_random": [512 bit random],
    "ed25519-pubkey": [Ed25519 public key],
    "slh-dsa-pubkey": [SLH-DSA public key],
    "ed25519-sig": [Ed25519 signature],
    "slh-sig": [SLH-DSA signature]
}

Client B then sends the same, but with type 12 (KEX_INIT_REPLY)

Client A then sends:
{
    "type": 13, (KEX_KEM),
    "mlkem-pubkey": [MLKEM public key],
    "server-identifier": [server_identifier],
    "ed25519-sig": [Ed25519 signature],
    "slh-sig": [SLH-DSA signature]
}

Client B compares server_identifier to its own server_identifier.
If they do not match, client B sends: {"type": 32, (KEX_SERVER_MISMATCH)} and disconnects.

If they match:
Client B generates the ML-KEM shared secret and an HQC keypair.
Client B generates a 512 bit Intermediary Key 1 (IK1) with ConcatKDFHash using the ML-KEM shared secret as input.
The derivation uses SHA3-512; info is "PQCProtocolIK1" encoded as UTF-8.
That IK1 is then used to encrypt the X25519 and HQC public key.
Then, finally, client B sends:
{
    "type": 14, (KEX_KEM_REPLY),
    "mlkem-ciphertext": [MLKEM ciphertext],
    "x25519-pubkey": [IK1 encrypted X25519 public key],
    "hqc-pubkey": [IK1 encrypted HQC public key],
    "server-identifier": [server_identifier],
    "ed25519-sig": [Ed25519 signature],
    "slh-sig": [SLH-DSA signature]
}

Client A compares server_identifier to its own server_identifier.
If they do not match, client A sends: {"type": 32, (KEX_SERVER_MISMATCH)} and disconnects.

If they match:
Client A decapsulates the MLKEM ciphertext and decrypts the X25519 and HQC public key.
Client A generates X25519 shared secret and HQC shared secret.
Client A then generates another 512 bit Intermediary Key 2 (IK2) with ConcatKDFHMAC using the X25519 shared secret as input and the IK1 as the salt.
The derivation uses SHA3-512; info is "PQCProtocolIK2" encoded as UTF-8.
Then, Client A sends:
{
    "type": 15, (KEX_DONE),
    "hqc-ciphertext": [IK2 encrypted HQC ciphertext],
    "x25519-pubkey": [IK1 encrypted X25519 public key],
    "ed25519-sig": [Ed25519 signature],
    "slh-sig": [SLH-DSA signature]
}

After B processes that message, both sides have:
IK1
IK2
X25519 shared secret
HQC shared secret
MLKEM shared secret
Client A's and B's randoms
Server identifier

Then both sides generate two root chain keys, the own root chain key, and the peer root chain key.
The own root chain key is ConcatKDFHMAC, with the MLKEM shared secret concatenated with the own client random as input and the X25519 shared secret as the salt.
The derivation uses SHA-512; info is "PQCProtocolRootChainKey" encoded as UTF-8.
The peer root chain key is the same but concatenated with the peer client random.
