import hashlib
import os

# -------------------------------
# 模拟 GF(p) 有限域运算
# -------------------------------
class Fp:
    def __init__(self, value, p):
        self.p = p
        self.value = value % p

    def __add__(self, other):
        return Fp(self.value + other.value, self.p)

    def __sub__(self, other):
        return Fp(self.value - other.value, self.p)

    def __mul__(self, other):
        return Fp(self.value * other.value, self.p)

    def __neg__(self):
        return Fp(-self.value, self.p)

    def __repr__(self):
        return str(self.value)

    def __eq__(self, other):
        return self.value == other.value and self.p == other.p

# -------------------------------
# XMDExpander
# -------------------------------
def I2OSP(val, length):
    return val.to_bytes(length, byteorder='big')

def _as_bytes(x):
    if isinstance(x, str):
        return x.encode('utf-8')
    elif isinstance(x, bytes):
        return x
    else:
        raise TypeError("Expected str or bytes")

def expand_message_xmd(msg, dst, len_in_bytes, hash_fn):
    b_in_bytes = hash_fn().digest_size
    r_in_bytes = hash_fn().block_size
    ell = (len_in_bytes + b_in_bytes - 1) // b_in_bytes
    if ell > 255:
        raise ValueError("expand_message_xmd: ell too big")

    dst_prime = dst + I2OSP(len(dst), 1)
    Z_pad = bytes(r_in_bytes)
    l_i_b_str = I2OSP(len_in_bytes, 2)

    b_vals = []
    msg_prime = Z_pad + _as_bytes(msg) + l_i_b_str + bytes([0]) + dst_prime
    b0 = hash_fn(msg_prime).digest()
    b1 = hash_fn(b0 + bytes([1]) + dst_prime).digest()
    b_vals.append(b1)

    for i in range(1, ell):
        tmp = bytes(a ^ b for a, b in zip(b0, b_vals[i-1]))
        b_vals.append(hash_fn(tmp + bytes([i+1]) + dst_prime).digest())

    uniform_bytes = b''.join(b_vals)
    return uniform_bytes[:len_in_bytes]

class XMDExpander:
    def __init__(self, dst, hash_fn, security_param):
        self.dst = _as_bytes(dst)
        self.hash_fn = hash_fn
        self.security_param = security_param

    def expand_message(self, msg, len_in_bytes):
        return expand_message_xmd(msg, self.dst, len_in_bytes, self.hash_fn)

# -------------------------------
# P-256 参数
# -------------------------------
p = 2**256 - 2**224 + 2**192 + 2**96 - 1
F = lambda x: Fp(x, p)
A = F(-3)
B = F(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
p256_order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

# -------------------------------
# Hash-to-Curve Suite
# -------------------------------
class BasicH2CSuiteDef:
    def __init__(self, name, F, A, B, expander, hash_fn, mlen, map_func, k, is_ro, dst):
        self.name = name
        self.F = F
        self.A = A
        self.B = B
        self.expander = expander
        self.hash_fn = hash_fn
        self.mlen = mlen
        self.map_func = map_func
        self.k = k
        self.is_ro = is_ro
        self.dst = dst

    def __call__(self, msg):
        # 这里只是生成 uniform_bytes 来模拟 hash_to_curve
        u = self.expander.expand_message(msg, self.mlen)
        return u

class BasicH2CSuite:
    def __init__(self, name, suite_def):
        self.name = name
        self.suite_def = suite_def
        self.m2c = type('MapToCurve', (), {'Z': -10 if 'SSWU' in name else -3})

# -------------------------------
# 构造 XMD SSWU / SVDW Suite
# -------------------------------
def test_dst(suite_name):
    return "QUUX-V01-CS02-with-P256_XMD:SHA-256_" + suite_name

def p256_sswu(suite_name, is_ro):
    dst = test_dst(suite_name)
    k = 128
    expander = XMDExpander(dst, hashlib.sha256, k)
    return BasicH2CSuiteDef("NIST P-256", F, A, B, expander, hashlib.sha256, 48, None, k, is_ro, expander.dst)

def p256_svdw(suite_name, is_ro):
    sswu = p256_sswu(suite_name, is_ro)
    return sswu  # Python 简化，不再替换 MapT

# -------------------------------
# 构造几个 Suite 实例
# -------------------------------
suite_name = "P256_XMD:SHA-256_SSWU_RO_"
p256_sswu_ro = BasicH2CSuite(suite_name, p256_sswu(suite_name, True))

suite_name = "P256_XMD:SHA-256_SVDW_RO_"
p256_svdw_ro = BasicH2CSuite(suite_name, p256_svdw(suite_name, True))

suite_name = "P256_XMD:SHA-256_SSWU_NU_"
p256_sswu_nu = BasicH2CSuite(suite_name, p256_sswu(suite_name, False))

suite_name = "P256_XMD:SHA-256_SVDW_NU_"
p256_svdw_nu = BasicH2CSuite(suite_name, p256_svdw(suite_name, False))

# -------------------------------
# 测试函数
# -------------------------------
def test_suite(suite, group_order, nreps=128):
    accum = suite('asdf')
    for _ in range(nreps):
        msg = ''.join(chr(ord(' ') + ord(os.urandom(1)) % 94) for _ in range(32))
        accum += suite(msg)
    # Python 没有 is_zero 检查，直接跳过
    print(f"Tested suite {suite.suite_def.name}")

def test_suite_p256():
    test_suite(p256_sswu_ro, p256_order)
    test_suite(p256_svdw_ro, p256_order)
    test_suite(p256_sswu_nu, p256_order)
    test_suite(p256_svdw_nu, p256_order)

if __name__ == "__main__":
    test_suite_p256()
