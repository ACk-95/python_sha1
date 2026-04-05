# Python SHA-1 Implementation

This repository contains a custom implementation of the SHA-1 hashing algorithm written in pure Python.

## Features
- Full SHA-1 implementation from scratch
- Supports incremental hashing with `update()`
- Compatible with Python's `hashlib` output
- Includes unit tests for validation

## Files
- `sha1.py` → SHA-1 algorithm implementation
- `test_sha1.py` → Unit tests for correctness and consistency

## Usage
```python
import sha1

data = b"hello world"
hash_value = sha1.sha1(data)

print(hash_value)
