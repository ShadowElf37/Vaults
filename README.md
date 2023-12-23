# Vaults v2.0
Simple Python script for making and managing encrypted vaults. Vaults use a symmetrically encrypted, randomly generated AES key to encode and decode data.

Requires pycryptodome (and opencv-python if you want image display).

Updates from v1.3:
- Switched to triple symmetric keys for improved performance
- Created a file system in the backend so that large files can be streamed off the disk

See bottom of vault.py for example usage.
