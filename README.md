# Vaults v3
Simple Python script for making and managing encrypted vaults. Vaults use a symmetrically encrypted, randomly generated AES key to encode and decode data.

Requires pycryptodome (and opencv-python if you want image display).

Updates from v2:
- Switched to symmetric keys for improved performance
- Lock/unlock mechanism to prevent repeated password inputs
- Data now rinsed several times

See `test()` function at the bottom of vault.py for example usage.
