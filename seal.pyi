from __future__ import annotations

from enum import IntEnum
from typing import Iterable, Sequence, TypeAlias, overload

import numpy as np
from numpy.typing import NDArray

__version__: str

ParmsId: TypeAlias = Sequence[int]
FloatLikeArray: TypeAlias = Iterable[float]
ComplexLikeArray: TypeAlias = Iterable[complex]
IntLikeArray: TypeAlias = Iterable[int]


class scheme_type(IntEnum):
    none: int
    bfv: int
    ckks: int
    bgv: int


class compr_mode_type(IntEnum):
    none: int
    zlib: int
    zstd: int


class sec_level_type(IntEnum):
    none: int
    tc128: int
    tc192: int
    tc256: int


class error_type(IntEnum):
    none: int
    success: int
    invalid_scheme: int
    invalid_coeff_modulus_size: int
    invalid_coeff_modulus_bit_count: int
    invalid_coeff_modulus_no_ntt: int
    invalid_poly_modulus_degree: int
    invalid_poly_modulus_degree_non_power_of_two: int
    invalid_parameters_too_large: int
    invalid_parameters_insecure: int
    failed_creating_rns_base: int
    invalid_plain_modulus_bit_count: int
    invalid_plain_modulus_coprimality: int
    invalid_plain_modulus_too_large: int
    invalid_plain_modulus_nonzero: int
    failed_creating_rns_tool: int


class VectorDouble(list[float]): ...
class VectorComplex(list[complex]): ...
class VectorUInt(list[int]): ...
class VectorInt(list[int]): ...


class MemoryPoolHandle:
    """Handle to a memory pool used by SEAL for temporary allocations."""

    def __init__(self) -> None:
        """Construct an uninitialized memory pool handle."""
        ...

    @staticmethod
    def Global() -> MemoryPoolHandle:
        """Return a handle to the global memory pool."""
        ...

    @staticmethod
    def ThreadLocal() -> MemoryPoolHandle:
        """Return a handle to the thread-local memory pool."""
        ...

    @staticmethod
    def New(clear_on_destruction: bool = False) -> MemoryPoolHandle:
        """Create a new independent memory pool."""
        ...

    def pool_count(self) -> int:
        """Return the number of memory pools referenced by this handle."""
        ...

    def alloc_byte_count(self) -> int:
        """Return the number of bytes allocated by the pool."""
        ...

    def use_count(self) -> int:
        """Return the reference count of the underlying pool."""
        ...

    def is_initialized(self) -> bool:
        """Return whether this handle points to an initialized pool."""
        ...


class MemoryManager:
    @staticmethod
    def GetPool() -> MemoryPoolHandle:
        """Return the default memory pool handle."""
        ...


class Modulus:
    """Represents an integer modulus used in encryption parameters."""

    def __init__(self, value: int) -> None:
        """Construct a modulus from an unsigned 64-bit integer."""
        ...

    def bit_count(self) -> int:
        """Return the bit length of the modulus."""
        ...

    def value(self) -> int:
        """Return the numeric value of the modulus."""
        ...

    def is_zero(self) -> bool:
        """Return whether the modulus is zero."""
        ...

    def is_prime(self) -> bool:
        """Return whether the modulus value is prime."""
        ...

    def reduce(self, value: int) -> int:
        """Reduce an integer modulo this modulus."""
        ...


class EncryptionParameters:
    """User-configurable encryption settings for a SEAL scheme."""

    @overload
    def __init__(self, scheme: scheme_type) -> None:
        """Create an empty set of encryption parameters for the given scheme."""
        ...

    @overload
    def __init__(self, other: EncryptionParameters) -> None:
        """Create a copy of an existing EncryptionParameters object."""
        ...

    def set_poly_modulus_degree(self, poly_modulus_degree: int) -> None:
        """Set the degree of the polynomial modulus."""
        ...

    def set_coeff_modulus(self, coeff_modulus: Sequence[Modulus]) -> None:
        """Set the coefficient modulus as a list of distinct prime moduli."""
        ...

    @overload
    def set_plain_modulus(self, plain_modulus: Modulus) -> None:
        """Set the plaintext modulus from a Modulus object."""
        ...

    @overload
    def set_plain_modulus(self, plain_modulus: int) -> None:
        """Set the plaintext modulus from an integer value."""
        ...

    def scheme(self) -> scheme_type:
        """Return the selected encryption scheme."""
        ...

    def poly_modulus_degree(self) -> int:
        """Return the degree of the polynomial modulus."""
        ...

    def coeff_modulus(self) -> Sequence[Modulus]:
        """Return the coefficient modulus chain."""
        ...

    def plain_modulus(self) -> Modulus:
        """Return the plaintext modulus."""
        ...

    @overload
    def save(self, path: str) -> None:
        """Serialize the encryption parameters to a file."""
        ...

    @overload
    def save(self, path: str, compr_mode: compr_mode_type) -> None:
        """Serialize the encryption parameters using the given compression mode."""
        ...

    def load(self, path: str) -> None:
        """Load serialized encryption parameters from a file."""
        ...

    def load_bytes(self, data: bytes) -> None:
        """Load serialized encryption parameters from bytes."""
        ...

    def save_size(self, compr_mode: compr_mode_type = ...) -> int:
        """Return the serialized size in bytes for the given compression mode."""
        ...

    def to_bytes(self, compr_mode: compr_mode_type = ...) -> bytes:
        """Serialize the encryption parameters to a Python bytes object."""
        ...


class EncryptionParameterQualifiers:
    """Precomputed validation results and capabilities of a parameter set."""

    parameter_error: error_type
    using_fft: bool
    using_ntt: bool
    using_batching: bool
    using_fast_plain_lift: bool
    using_descending_modulus_chain: bool
    sec_level: sec_level_type

    def parameters_set(self) -> bool:
        """Return whether the parameters were validated successfully."""
        ...

    def parameter_error_name(self) -> str:
        """Return the symbolic name of the validation error."""
        ...

    def parameter_error_message(self) -> str:
        """Return a human-readable explanation of the validation error."""
        ...


class ContextData:
    """Precomputation data for one level in the modulus switching chain."""

    def parms(self) -> EncryptionParameters:
        """Return the encryption parameters for this context level."""
        ...

    def parms_id(self) -> ParmsId:
        """Return the unique parameter identifier for this level."""
        ...

    def qualifiers(self) -> EncryptionParameterQualifiers:
        """Return qualifiers derived from these parameters."""
        ...

    def total_coeff_modulus(self) -> int:
        """Return the product of all coefficient modulus primes."""
        ...

    def total_coeff_modulus_bit_count(self) -> int:
        """Return the bit count of the total coefficient modulus."""
        ...

    def next_context_data(self) -> ContextData | None:
        """Return the next lower level in the modulus switching chain."""
        ...

    def chain_index(self) -> int:
        """Return the chain index for this context level."""
        ...


class SEALContext:
    """Validates parameters and stores heavy-weight SEAL precomputations."""

    def __init__(
        self,
        parms: EncryptionParameters,
        expand_mod_chain: bool = True,
        sec_level: sec_level_type = sec_level_type.tc128,
    ) -> None:
        """Create a context and optionally expand the modulus switching chain."""
        ...

    def get_context_data(self, parms_id: ParmsId) -> ContextData | None:
        """Return ContextData for a specific parms_id."""
        ...

    def key_context_data(self) -> ContextData:
        """Return the key-level ContextData."""
        ...

    def first_context_data(self) -> ContextData:
        """Return the first data-level ContextData in the chain."""
        ...

    def last_context_data(self) -> ContextData:
        """Return the last valid ContextData in the chain."""
        ...

    def parameters_set(self) -> bool:
        """Return whether the parameters were validated successfully."""
        ...

    def parameter_error_name(self) -> str:
        """Return the symbolic name of the validation result."""
        ...

    def parameter_error_message(self) -> str:
        """Return a human-readable validation message."""
        ...

    def first_parms_id(self) -> ParmsId:
        """Return the parms_id for the first data-level parameters."""
        ...

    def last_parms_id(self) -> ParmsId:
        """Return the parms_id for the last valid parameters in the chain."""
        ...

    def using_keyswitching(self) -> bool:
        """Return whether the parameter chain supports key switching."""
        ...

    def from_cipher_str(self, data: bytes | str) -> Ciphertext:
        """Deserialize a Ciphertext from serialized bytes."""
        ...

    def from_plain_str(self, data: bytes | str) -> Plaintext:
        """Deserialize a Plaintext from serialized bytes."""
        ...

    def from_secret_str(self, data: bytes | str) -> SecretKey:
        """Deserialize a SecretKey from serialized bytes."""
        ...

    def from_public_str(self, data: bytes | str) -> PublicKey:
        """Deserialize a PublicKey from serialized bytes."""
        ...

    def from_relin_str(self, data: bytes | str) -> RelinKeys:
        """Deserialize RelinKeys from serialized bytes."""
        ...

    def from_galois_str(self, data: bytes | str) -> GaloisKeys:
        """Deserialize GaloisKeys from serialized bytes."""
        ...


class CoeffModulus:
    """Factory helpers for constructing coefficient modulus chains."""

    @staticmethod
    def MaxBitCount(poly_modulus_degree: int, sec_level: sec_level_type = sec_level_type.tc128) -> int:
        """Return the maximum safe total bit count for the coefficient modulus."""
        ...

    @staticmethod
    def BFVDefault(poly_modulus_degree: int, sec_level: sec_level_type = sec_level_type.tc128) -> Sequence[Modulus]:
        """Return SEAL's default BFV/BGV coefficient modulus."""
        ...

    @overload
    @staticmethod
    def Create(poly_modulus_degree: int, bit_sizes: Sequence[int]) -> Sequence[Modulus]:
        """Create a coefficient modulus chain with primes of the given bit sizes."""
        ...

    @overload
    @staticmethod
    def Create(poly_modulus_degree: int, plain_modulus: Modulus, bit_sizes: Sequence[int]) -> Sequence[Modulus]:
        """Create a coefficient modulus chain tailored to a plaintext modulus."""
        ...


class PlainModulus:
    """Factory helpers for constructing plaintext moduli."""

    @overload
    @staticmethod
    def Batching(poly_modulus_degree: int, bit_size: int) -> Modulus:
        """Create one batching-compatible plaintext modulus."""
        ...

    @overload
    @staticmethod
    def Batching(poly_modulus_degree: int, bit_sizes: Sequence[int]) -> Sequence[Modulus]:
        """Create batching-compatible plaintext moduli for the given bit sizes."""
        ...


class Plaintext:
    """Plaintext polynomial container used by BFV/BGV and CKKS."""

    @overload
    def __init__(self) -> None:
        """Construct an empty plaintext with no allocated data."""
        ...

    @overload
    def __init__(self, coeff_count: int) -> None:
        """Construct a zero plaintext with the given coefficient count."""
        ...

    @overload
    def __init__(self, coeff_count: int, capacity: int) -> None:
        """Construct a zero plaintext with explicit coefficient count and capacity."""
        ...

    @overload
    def __init__(self, hex_poly: str) -> None:
        """Construct a plaintext from its hexadecimal polynomial string form."""
        ...

    @overload
    def __init__(self, other: Plaintext) -> None:
        """Construct a copy of an existing plaintext."""
        ...

    @overload
    def set_zero(self) -> None:
        """Set all coefficients to zero."""
        ...

    @overload
    def set_zero(self, start_coeff: int) -> None:
        """Set coefficients from start_coeff to the end to zero."""
        ...

    @overload
    def set_zero(self, start_coeff: int, length: int) -> None:
        """Set a range of coefficients to zero."""
        ...

    def is_zero(self) -> bool:
        """Return whether all coefficients are zero."""
        ...

    def capacity(self) -> int:
        """Return the allocation capacity measured in coefficients."""
        ...

    def coeff_count(self) -> int:
        """Return the number of coefficients stored in the plaintext."""
        ...

    def significant_coeff_count(self) -> int:
        """Return the number of significant coefficients."""
        ...

    def nonzero_coeff_count(self) -> int:
        """Return the number of non-zero coefficients."""
        ...

    def to_string(self) -> str:
        """Return the plaintext polynomial formatted as a hexadecimal string."""
        ...

    def is_ntt_form(self) -> bool:
        """Return whether the plaintext is stored in NTT form."""
        ...

    def parms_id(self) -> ParmsId:
        """Return the parms_id associated with this plaintext."""
        ...

    @overload
    def scale(self) -> float:
        """Return the CKKS scale attached to this plaintext."""
        ...

    @overload
    def scale(self, value: float) -> None:
        """Set the CKKS scale attached to this plaintext."""
        ...

    @overload
    def save(self, path: str) -> None:
        """Serialize the plaintext to a file."""
        ...

    @overload
    def save(self, path: str, compr_mode: compr_mode_type) -> None:
        """Serialize the plaintext using the given compression mode."""
        ...

    def load(self, context: SEALContext, path: str) -> None:
        """Load a serialized plaintext from a file and validate it."""
        ...

    def load_bytes(self, context: SEALContext, data: bytes) -> None:
        """Load a serialized plaintext from bytes and validate it."""
        ...

    def save_size(self, compr_mode: compr_mode_type = ...) -> int:
        """Return the serialized size in bytes for the given compression mode."""
        ...

    def to_bytes(self, compr_mode: compr_mode_type = ...) -> bytes:
        """Serialize the plaintext to a Python bytes object."""
        ...


class Ciphertext:
    """Encrypted value together with parameter metadata."""

    @overload
    def __init__(self) -> None:
        """Construct an empty ciphertext with no allocated data."""
        ...

    @overload
    def __init__(self, context: SEALContext) -> None:
        """Construct an empty ciphertext at the highest data level."""
        ...

    @overload
    def __init__(self, context: SEALContext, parms_id: ParmsId) -> None:
        """Construct an empty ciphertext initialized for a specific parms_id."""
        ...

    @overload
    def __init__(self, context: SEALContext, parms_id: ParmsId, size_capacity: int) -> None:
        """Construct an empty ciphertext with explicit polynomial capacity."""
        ...

    @overload
    def __init__(self, other: Ciphertext) -> None:
        """Construct a copy of an existing ciphertext."""
        ...

    def coeff_modulus_size(self) -> int:
        """Return the number of coefficient modulus primes."""
        ...

    def poly_modulus_degree(self) -> int:
        """Return the polynomial modulus degree."""
        ...

    def size(self) -> int:
        """Return the number of polynomials in the ciphertext."""
        ...

    def size_capacity(self) -> int:
        """Return the allocated ciphertext capacity."""
        ...

    def is_transparent(self) -> bool:
        """Return whether the ciphertext is transparent."""
        ...

    def is_ntt_form(self) -> bool:
        """Return whether the ciphertext is stored in NTT form."""
        ...

    def parms_id(self) -> ParmsId:
        """Return the parms_id associated with this ciphertext."""
        ...

    @overload
    def scale(self) -> float:
        """Return the CKKS scale attached to this ciphertext."""
        ...

    @overload
    def scale(self, value: float) -> None:
        """Set the CKKS scale attached to this ciphertext."""
        ...

    @overload
    def save(self, path: str) -> None:
        """Serialize the ciphertext to a file."""
        ...

    @overload
    def save(self, path: str, compr_mode: compr_mode_type) -> None:
        """Serialize the ciphertext using the given compression mode."""
        ...

    def load(self, context: SEALContext, path: str) -> None:
        """Load a serialized ciphertext from a file and validate it."""
        ...

    def load_bytes(self, context: SEALContext, data: bytes) -> None:
        """Load a serialized ciphertext from bytes and validate it."""
        ...

    def save_size(self, compr_mode: compr_mode_type = ...) -> int:
        """Return the serialized size in bytes for the given compression mode."""
        ...

    def to_string(self, compr_mode: compr_mode_type = ...) -> bytes:
        """Serialize the ciphertext to a Python bytes object."""
        ...


class SecretKey:
    """Stores the secret key used for decryption and symmetric encryption."""

    @overload
    def __init__(self) -> None:
        """Construct an empty secret key."""
        ...

    @overload
    def __init__(self, other: SecretKey) -> None:
        """Construct a copy of an existing secret key."""
        ...

    def parms_id(self) -> ParmsId:
        """Return the parms_id associated with the secret key."""
        ...

    def save(self, path: str) -> None:
        """Serialize the secret key to a file."""
        ...

    def load(self, context: SEALContext, path: str) -> None:
        """Load a serialized secret key from a file."""
        ...

    def to_string(self) -> bytes:
        """Serialize the secret key to a Python bytes object."""
        ...


class PublicKey:
    """Stores the public key used for public-key encryption."""

    @overload
    def __init__(self) -> None:
        """Construct an empty public key."""
        ...

    @overload
    def __init__(self, other: PublicKey) -> None:
        """Construct a copy of an existing public key."""
        ...

    def parms_id(self) -> ParmsId:
        """Return the parms_id associated with the public key."""
        ...

    def save(self, path: str) -> None:
        """Serialize the public key to a file."""
        ...

    def load(self, context: SEALContext, path: str) -> None:
        """Load a serialized public key from a file."""
        ...

    def to_string(self) -> bytes:
        """Serialize the public key to a Python bytes object."""
        ...


class KSwitchKeys:
    """Base container for key switching key material."""

    @overload
    def __init__(self) -> None:
        """Construct an empty key switching key container."""
        ...

    @overload
    def __init__(self, other: KSwitchKeys) -> None:
        """Construct a copy of an existing key switching key container."""
        ...

    def size(self) -> int:
        """Return the number of stored key switching key sets."""
        ...

    def parms_id(self) -> ParmsId:
        """Return the parms_id associated with this key set."""
        ...

    def save(self, path: str) -> None:
        """Serialize the key switching keys to a file."""
        ...

    def load(self, context: SEALContext, path: str) -> None:
        """Load serialized key switching keys from a file."""
        ...


class RelinKeys(KSwitchKeys):
    """Relinearization keys used to shrink ciphertext size after multiplication."""

    @overload
    def __init__(self) -> None:
        """Construct an empty set of relinearization keys."""
        ...

    @overload
    def __init__(self, other: KSwitchKeys) -> None:
        """Construct relinearization keys from a key switching key base object."""
        ...

    @staticmethod
    def get_index(key_power: int) -> int:
        """Map a key power to SEAL's internal storage index."""
        ...

    def has_key(self, key_power: int) -> bool:
        """Return whether a relinearization key exists for key_power."""
        ...

    def to_string(self) -> bytes:
        """Serialize the relinearization keys to a Python bytes object."""
        ...


class GaloisKeys(KSwitchKeys):
    """Galois keys used for rotations and CKKS complex conjugation."""

    @overload
    def __init__(self) -> None:
        """Construct an empty set of Galois keys."""
        ...

    @overload
    def __init__(self, other: KSwitchKeys) -> None:
        """Construct Galois keys from a key switching key base object."""
        ...

    @staticmethod
    def get_index(galois_elt: int) -> int:
        """Map a Galois element to SEAL's internal storage index."""
        ...

    def has_key(self, galois_elt: int) -> bool:
        """Return whether a Galois key exists for galois_elt."""
        ...

    def to_string(self) -> bytes:
        """Serialize the Galois keys to a Python bytes object."""
        ...


class KeyGenerator:
    """Generate secret, public, relinearization, and Galois keys."""

    @overload
    def __init__(self, context: SEALContext) -> None:
        """Create a key generator and generate a fresh secret key."""
        ...

    @overload
    def __init__(self, context: SEALContext, secret_key: SecretKey) -> None:
        """Create a key generator from an existing secret key."""
        ...

    def secret_key(self) -> SecretKey:
        """Return the secret key managed by this generator."""
        ...

    @overload
    def create_public_key(self) -> PublicKey:
        """Generate and return a new public key."""
        ...

    @overload
    def create_public_key(self, destination: PublicKey) -> None:
        """Generate a public key and store it in destination."""
        ...

    @overload
    def create_relin_keys(self) -> RelinKeys:
        """Generate and return relinearization keys."""
        ...

    @overload
    def create_relin_keys(self, destination: RelinKeys) -> None:
        """Generate relinearization keys and store them in destination."""
        ...

    @overload
    def create_galois_keys(self) -> GaloisKeys:
        """Generate and return all supported Galois keys."""
        ...

    @overload
    def create_galois_keys(self, destination: GaloisKeys) -> None:
        """Generate all supported Galois keys and store them in destination."""
        ...

    @overload
    def create_galois_keys(self, galois_elts: Sequence[int], destination: GaloisKeys) -> None:
        """Generate Galois keys for the requested rotation steps."""
        ...


class Encryptor:
    """Encrypt plaintexts using a public key or a secret key."""

    @overload
    def __init__(self, context: SEALContext, public_key: PublicKey) -> None:
        """Create an encryptor configured for public-key encryption."""
        ...

    @overload
    def __init__(self, context: SEALContext, secret_key: SecretKey) -> None:
        """Create an encryptor configured for secret-key encryption."""
        ...

    @overload
    def __init__(self, context: SEALContext, public_key: PublicKey, secret_key: SecretKey) -> None:
        """Create an encryptor configured with both public and secret keys."""
        ...

    def set_public_key(self, public_key: PublicKey) -> None:
        """Set or replace the public key used for encryption."""
        ...

    def set_secret_key(self, secret_key: SecretKey) -> None:
        """Set or replace the secret key used for symmetric encryption."""
        ...

    @overload
    def encrypt_zero(self) -> Ciphertext:
        """Encrypt zero at the first data level and return the ciphertext."""
        ...

    @overload
    def encrypt_zero(self, destination: Ciphertext) -> None:
        """Encrypt zero at the first data level into destination."""
        ...

    @overload
    def encrypt_zero(self, parms_id: ParmsId) -> Ciphertext:
        """Encrypt zero for the specified parms_id and return the ciphertext."""
        ...

    @overload
    def encrypt_zero(self, parms_id: ParmsId, destination: Ciphertext) -> None:
        """Encrypt zero for the specified parms_id into destination."""
        ...

    @overload
    def encrypt(self, plain: Plaintext) -> Ciphertext:
        """Encrypt a plaintext with the public key and return the ciphertext."""
        ...

    @overload
    def encrypt(self, plain: Plaintext, destination: Ciphertext) -> None:
        """Encrypt a plaintext with the public key into destination."""
        ...

    @overload
    def encrypt_symmetric(self, plain: Plaintext) -> Ciphertext:
        """Encrypt a plaintext with the secret key and return the ciphertext."""
        ...

    @overload
    def encrypt_symmetric(self, plain: Plaintext, destination: Ciphertext) -> None:
        """Encrypt a plaintext with the secret key into destination."""
        ...


class Evaluator:
    """Apply homomorphic operations to ciphertexts and plaintexts."""

    def __init__(self, context: SEALContext) -> None:
        """Create an evaluator for the given context."""
        ...

    def negate_inplace(self, encrypted: Ciphertext) -> None:
        """Negate a ciphertext in place."""
        ...

    def negate(self, encrypted1: Ciphertext) -> Ciphertext:
        """Negate a ciphertext and return the result."""
        ...

    def add_inplace(self, encrypted1: Ciphertext, encrypted2: Ciphertext) -> None:
        """Add two ciphertexts and store the result in encrypted1."""
        ...

    def add(self, encrypted1: Ciphertext, encrypted2: Ciphertext) -> Ciphertext:
        """Add two ciphertexts and return the result."""
        ...

    def add_many(self, encrypteds: Sequence[Ciphertext]) -> Ciphertext:
        """Add many ciphertexts together and return the sum."""
        ...

    def sub_inplace(self, encrypted1: Ciphertext, encrypted2: Ciphertext) -> None:
        """Subtract encrypted2 from encrypted1 in place."""
        ...

    def sub(self, encrypted1: Ciphertext, encrypted2: Ciphertext) -> Ciphertext:
        """Subtract two ciphertexts and return the result."""
        ...

    def multiply_inplace(self, encrypted1: Ciphertext, encrypted2: Ciphertext) -> None:
        """Multiply two ciphertexts and store the result in encrypted1."""
        ...

    def multiply(self, encrypted1: Ciphertext, encrypted2: Ciphertext) -> Ciphertext:
        """Multiply two ciphertexts and return the result."""
        ...

    def square_inplace(self, encrypted1: Ciphertext) -> None:
        """Square a ciphertext in place."""
        ...

    def square(self, encrypted1: Ciphertext) -> Ciphertext:
        """Square a ciphertext and return the result."""
        ...

    def relinearize_inplace(self, encrypted1: Ciphertext, relin_keys: RelinKeys) -> None:
        """Relinearize a ciphertext in place using relinearization keys."""
        ...

    def relinearize(self, encrypted1: Ciphertext, relin_keys: RelinKeys) -> Ciphertext:
        """Relinearize a ciphertext and return the result."""
        ...
    @overload
    def mod_switch_to_next(self, encrypted: Ciphertext) -> Ciphertext:
        """Mod-switch a ciphertext to the next level and return the result."""
        ...

    @overload
    def mod_switch_to_next(self, plain: Plaintext) -> Plaintext:
        """Mod-switch a plaintext to the next level and return the result."""
        ...

    @overload
    def mod_switch_to_next_inplace(self, encrypted: Ciphertext) -> None:
        """Mod-switch a ciphertext to the next level in place."""
        ...

    @overload
    def mod_switch_to_next_inplace(self, plain: Plaintext) -> None:
        """Mod-switch a plaintext to the next level in place."""
        ...

    @overload
    def mod_switch_to_inplace(self, encrypted: Ciphertext, parms_id: ParmsId) -> None:
        """Mod-switch a ciphertext in place to the specified parms_id."""
        ...

    @overload
    def mod_switch_to_inplace(self, plain: Plaintext, parms_id: ParmsId) -> None:
        """Mod-switch a plaintext in place to the specified parms_id."""
        ...

    @overload
    def mod_switch_to(self, encrypted: Ciphertext, parms_id: ParmsId) -> Ciphertext:
        """Mod-switch a ciphertext to the specified parms_id and return it."""
        ...

    @overload
    def mod_switch_to(self, plain: Plaintext, parms_id: ParmsId) -> Plaintext:
        """Mod-switch a plaintext to the specified parms_id and return it."""
        ...

    def rescale_to_next(self, encrypted: Ciphertext) -> Ciphertext:
        """Rescale a CKKS ciphertext to the next level and return the result."""
        ...

    def rescale_to_next_inplace(self, encrypted: Ciphertext) -> None:
        """Rescale a CKKS ciphertext to the next level in place."""
        ...

    def rescale_to_inplace(self, encrypted: Ciphertext, parms_id: ParmsId) -> None:
        """Rescale a CKKS ciphertext in place to the specified parms_id."""
        ...

    def rescale_to(self, encrypted: Ciphertext, parms_id: ParmsId) -> Ciphertext:
        """Rescale a CKKS ciphertext to the specified parms_id and return it."""
        ...

    def multiply_many(self, encrypteds: Sequence[Ciphertext], relin_keys: RelinKeys) -> Ciphertext:
        """Multiply many ciphertexts together and return the result."""
        ...

    def exponentiate_inplace(self, encrypted: Ciphertext, exponent: int, relin_keys: RelinKeys) -> None:
        """Raise a ciphertext to a power in place."""
        ...

    def exponentiate(self, encrypted: Ciphertext, exponent: int, relin_keys: RelinKeys) -> Ciphertext:
        """Raise a ciphertext to a power and return the result."""
        ...

    def add_plain_inplace(self, encrypted: Ciphertext, plain: Plaintext) -> None:
        """Add a plaintext to a ciphertext in place."""
        ...

    def add_plain(self, encrypted: Ciphertext, plain: Plaintext) -> Ciphertext:
        """Add a plaintext to a ciphertext and return the result."""
        ...

    def sub_plain_inplace(self, encrypted: Ciphertext, plain: Plaintext) -> None:
        """Subtract a plaintext from a ciphertext in place."""
        ...

    def sub_plain(self, encrypted: Ciphertext, plain: Plaintext) -> Ciphertext:
        """Subtract a plaintext from a ciphertext and return the result."""
        ...

    def multiply_plain_inplace(self, encrypted: Ciphertext, plain: Plaintext) -> None:
        """Multiply a ciphertext by a plaintext in place."""
        ...

    def multiply_plain(self, encrypted: Ciphertext, plain: Plaintext) -> Ciphertext:
        """Multiply a ciphertext by a plaintext and return the result."""
        ...

    @overload
    def transform_to_ntt_inplace(self, plain: Plaintext, parms_id: ParmsId) -> None:
        """Transform a plaintext to NTT form in place."""
        ...

    @overload
    def transform_to_ntt_inplace(self, encrypted: Ciphertext) -> None:
        """Transform a ciphertext to NTT form in place."""
        ...

    @overload
    def transform_to_ntt(self, plain: Plaintext, parms_id: ParmsId) -> Plaintext:
        """Transform a plaintext to NTT form and return the result."""
        ...

    @overload
    def transform_to_ntt(self, encrypted: Ciphertext) -> Ciphertext:
        """Transform a ciphertext to NTT form and return the result."""
        ...

    def transform_from_ntt_inplace(self, encrypted: Ciphertext) -> None:
        """Transform an NTT-form ciphertext back to coefficient form in place."""
        ...

    def transform_from_ntt(self, encrypted_ntt: Ciphertext) -> Ciphertext:
        """Transform an NTT-form ciphertext back to coefficient form."""
        ...

    def apply_galois_inplace(self, encrypted: Ciphertext, galois_elt: int, galois_keys: GaloisKeys) -> None:
        """Apply a Galois automorphism to a ciphertext in place."""
        ...

    def apply_galois(self, encrypted: Ciphertext, galois_elt: int, galois_keys: GaloisKeys) -> Ciphertext:
        """Apply a Galois automorphism to a ciphertext and return the result."""
        ...

    def rotate_rows_inplace(self, encrypted: Ciphertext, steps: int, galois_keys: GaloisKeys) -> None:
        """Rotate BFV/BGV batching rows in place."""
        ...

    def rotate_rows(self, encrypted: Ciphertext, steps: int, galois_keys: GaloisKeys) -> Ciphertext:
        """Rotate BFV/BGV batching rows and return the result."""
        ...

    def rotate_columns_inplace(self, encrypted: Ciphertext, galois_keys: GaloisKeys) -> None:
        """Rotate BFV/BGV batching columns in place."""
        ...

    def rotate_columns(self, encrypted: Ciphertext, galois_keys: GaloisKeys) -> Ciphertext:
        """Rotate BFV/BGV batching columns and return the result."""
        ...

    def rotate_vector_inplace(self, encrypted: Ciphertext, steps: int, galois_keys: GaloisKeys) -> None:
        """Rotate a CKKS vector in place."""
        ...

    def rotate_vector(self, encrypted: Ciphertext, steps: int, galois_keys: GaloisKeys) -> Ciphertext:
        """Rotate a CKKS vector and return the result."""
        ...

    def complex_conjugate_inplace(self, encrypted: Ciphertext, galois_keys: GaloisKeys) -> None:
        """Apply CKKS complex conjugation in place."""
        ...

    def complex_conjugate(self, encrypted: Ciphertext, galois_keys: GaloisKeys) -> Ciphertext:
        """Apply CKKS complex conjugation and return the result."""
        ...


class CKKSEncoder:
    """Encode floating-point and complex vectors into CKKS plaintexts."""

    def __init__(self, context: SEALContext) -> None:
        """Create a CKKS encoder for the given context."""
        ...

    def slot_count(self) -> int:
        """Return the number of SIMD slots available for CKKS encoding."""
        ...

    @overload
    def encode(self, values: FloatLikeArray, scale: float) -> Plaintext:
        """Encode real values and return the plaintext."""
        ...

    @overload
    def encode(self, values: FloatLikeArray, scale: float, destination: Plaintext) -> None:
        """Encode real values into destination."""
        ...

    @overload
    def encode(self, value: float, scale: float) -> Plaintext:
        """Encode one real value and return the plaintext."""
        ...

    @overload
    def encode(self, value: float, scale: float, destination: Plaintext) -> None:
        """Encode one real value into destination."""
        ...

    @overload
    def encode(self, value: int) -> Plaintext:
        """Encode one integer exactly into a CKKS plaintext."""
        ...

    @overload
    def encode(self, value: int, destination: Plaintext) -> None:
        """Encode one integer exactly into destination."""
        ...

    @overload
    def encode_complex(self, values: ComplexLikeArray, scale: float) -> Plaintext:
        """Encode complex values and return the plaintext."""
        ...

    @overload
    def encode_complex(self, values: ComplexLikeArray, scale: float, destination: Plaintext) -> None:
        """Encode complex values into destination."""
        ...

    @overload
    def encode_complex(self, value: complex, scale: float) -> Plaintext:
        """Encode one complex value and return the plaintext."""
        ...

    @overload
    def encode_complex(self, value: complex, scale: float, destination: Plaintext) -> None:
        """Encode one complex value into destination."""
        ...

    def decode(self, plain: Plaintext) -> NDArray[np.float64]:
        """Decode a CKKS plaintext into a NumPy array of real values."""
        ...

    def decode_complex(self, plain: Plaintext) -> NDArray[np.complex128]:
        """Decode a CKKS plaintext into a NumPy array of complex values."""
        ...


class Decryptor:
    """Decrypt ciphertexts and inspect their remaining noise budget."""

    def __init__(self, context: SEALContext, secret_key: SecretKey) -> None:
        """Create a decryptor for the given context and secret key."""
        ...

    @overload
    def decrypt(self, encrypted: Ciphertext, destination: Plaintext) -> None:
        """Decrypt a ciphertext into destination."""
        ...

    @overload
    def decrypt(self, encrypted: Ciphertext) -> Plaintext:
        """Decrypt a ciphertext and return the plaintext."""
        ...

    def invariant_noise_budget(self, encrypted: Ciphertext) -> int:
        """Return the invariant noise budget of a ciphertext in bits."""
        ...


class BatchEncoder:
    """Encode integer vectors into BFV/BGV batching plaintexts."""

    def __init__(self, context: SEALContext) -> None:
        """Create a batch encoder for the given context."""
        ...

    def slot_count(self) -> int:
        """Return the number of batching slots available."""
        ...

    @overload
    def encode(self, values: Sequence[int], destination: Plaintext) -> None:
        """Encode integers into destination."""
        ...

    @overload
    def encode(self, values: IntLikeArray) -> Plaintext:
        """Encode integers and return the plaintext."""
        ...

    def decode(self, plain: Plaintext) -> NDArray[np.int64]:
        """Decode a batched plaintext into signed 64-bit integers."""
        ...

    def decode_uint64(self, plain: Plaintext) -> NDArray[np.uint64]:
        """Decode a batched plaintext into unsigned 64-bit integers."""
        ...
