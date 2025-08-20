import hashlib
import struct
import os
import sys
import groups
from ecdsa.curves import NIST256p,NIST384p,NIST521p


# 辅助函数：将大整数转字节串 (I2OSP, RFC 3447)
def I2OSP(val, length):
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError("bad I2OSP call: val=%d length=%d" % (val, length))
    ret = bytearray(length)
    for idx in range(length - 1, -1, -1):
        ret[idx] = val & 0xff
        val >>= 8
    return bytes(ret)

# 辅助函数：统一转 bytes
_as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")

# 定义 Ciphersuite
from collections import namedtuple
Ciphersuite = namedtuple("Ciphersuite", ["name", "identifier", "group", "H"])


# 初始化一个 suite 示例

ciphersuite_ristretto255_sha512 = "ristretto255-SHA512"
ciphersuite_decaf448_shake256 = "decaf448-SHAKE256"
ciphersuite_p256_sha256 = "P256-SHA256"
ciphersuite_p384_sha384 = "P384-SHA384"
ciphersuite_p521_sha512 = "P521-SHA512"

oprf_ciphersuites = {
    ciphersuite_ristretto255_sha512: Ciphersuite("OPRF(ristretto255, SHA-512)", ciphersuite_ristretto255_sha512, GroupRistretto255(), hashlib.sha512),
    ciphersuite_decaf448_shake256: Ciphersuite("OPRF(decaf448, SHAKE256)", ciphersuite_decaf448_shake256, GroupDecaf448(), hashlib.shake_256),
    ciphersuite_p256_sha256: Ciphersuite("OPRF(P-256, SHA-256)", ciphersuite_p256_sha256, GroupP256(), hashlib.sha256),
    ciphersuite_p384_sha384: Ciphersuite("OPRF(P-384, SHA-384)", ciphersuite_p384_sha384, GroupP384(), hashlib.sha384),
    ciphersuite_p521_sha512: Ciphersuite("OPRF(P-521, SHA-512)", ciphersuite_p521_sha512, GroupP521(), hashlib.sha512),
}

def identifer_to_suite(identifier):
    if identifier not in oprf_ciphersuites:
        raise Exception("Unknown ciphersuite")
    return oprf_ciphersuites[identifier]

def suitehash(x, suite):
    if suite == ciphersuite_ristretto255_sha512:
        return hashlib.sha512(x).digest()
    elif suite == ciphersuite_decaf448_shake256:
        return hashlib.shake_256(x).digest(64)
    elif suite == ciphersuite_p256_sha256:
        return hashlib.sha256(x).digest()
    elif suite == ciphersuite_p384_sha384:
        return hashlib.sha384(x).digest()
    elif suite == ciphersuite_p521_sha512:
        return hashlib.sha512(x).digest()
    else:
        raise Exception("Unknown ciphersuite")
try:
    from groups import GroupP256, GroupP384, GroupP521, GroupRistretto255, GroupDecaf448
except ImportError as e:
    sys.exit("Error loading preprocessed sage files. Try running `make setup && make clean pyfiles`. Full error: " + str(e))



# 上下文类
class Context:
    def __init__(self, version, mode, identifier):
        self.suite = identifer_to_suite(identifier)
        self.mode = mode
        self.identifier = identifier
        self.context_string = _as_bytes(version) + _as_bytes(identifier)

    def group_domain_separation_tag(self):
        return _as_bytes("HashToGroup-") + self.context_string

    def scalar_domain_separation_tag(self):
        return _as_bytes("HashToScalar-") + self.context_string

    def domain_separation_tag(self, prefix):
        return _as_bytes(prefix) + self.context_string

# OPRF 客户端上下文
class OPRFClientContext(Context):
    def __init__(self, version, mode, suite):
        super().__init__(version, mode, suite)

    def blind(self, x, rng=None):
        blind = self.suite.group.random_scalar(rng)
        input_element = self.suite.group.hash_to_group(x, self.group_domain_separation_tag())
        if input_element == self.suite.group.identity():
            raise Exception("InvalidInputError")
        blinded_element = (blind * input_element) % self.suite.group.order()
        return blind, blinded_element

    def unblind(self, blind, evaluated_element, blinded_element, proof=None):
        blind_inv = pow(blind, -1, self.suite.group.order())
        N = (blind_inv * evaluated_element) % self.suite.group.order()
        unblinded_element = self.suite.group.serialize(N)
        return unblinded_element

    def finalize(self, x, blind, evaluated_element, blinded_element, proof, info):
        unblinded_element = self.unblind(blind, evaluated_element, blinded_element, proof)
        finalize_input = (
            I2OSP(len(x), 2) + x +
            I2OSP(len(unblinded_element), 2) + unblinded_element +
            _as_bytes("Finalize")
        )
        return suitehash(finalize_input, self.identifier)
class OPRFServerContext(Context):
    def __init__(self, version, mode, suite, skS, pkS):
        Context.__init__(self, version, mode, suite)
        self.skS = skS
        self.pkS = pkS

    def internal_evaluate(self, blinded_element):
        evaluated_element = self.skS * blinded_element
        return evaluated_element

    def blind_evaluate(self, blinded_element, info, rng):
        evaluated_element = self.internal_evaluate(blinded_element)
        return evaluated_element, None, None

    def evaluate_without_proof(self, blinded_element, info):
        return self.internal_evaluate(blinded_element)

    def evaluate(self, x, info):
        input_element = self.suite.group.hash_to_group(x, self.group_domain_separation_tag())
        if input_element == self.suite.group.identity():
            raise Exception("InvalidInputError")
        evaluated_element = self.internal_evaluate(input_element)
        issued_element = self.suite.group.serialize(evaluated_element)
        finalize_input = I2OSP(len(x), 2 ) + x             
        + I2OSP(len(issued_element), 2 ) + issued_element             
        + _as_bytes("Finalize")

        return suitehash(finalize_input, self.identifier)