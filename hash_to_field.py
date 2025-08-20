import struct
import hashlib
import sys
import json

#兼顾了python2和python3的_as_bytes的写法，将消息转换为字符串；还有字符串异或的写法，我也不知道为什么
if sys.version_info[0] == 3:
    _as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")
    _strxor = lambda str1, str2: bytes( s1 ^ s2 for (s1, s2) in zip(str1, str2) )
else:
    _as_bytes = lambda x: x

#将字符串转换为十六进制表示
def to_hex(octet_string):
    if isinstance(octet_string, str):
        return "".join("{:02x}".format(ord(c)) for c in octet_string)
    assert isinstance(octet_string, bytes)
    return "".join("{:02x}".format(c) for c in octet_string)

#把整数转换为字节串的函数
def I2OSP(val, length):
    if val < 0 or val >= (1 << (8 * length)):
        raise ValueError("bad I2OSP call: val=%d length=%d" % (val, length))
    ret = bytearray(length)
    for idx in range(length - 1, -1, -1):
        ret[idx] = val & 0xff
        val >>= 8
    return bytes(ret)


#把字节串转换为整数的函数
def OS2IP(octets, skip_assert=False):
    ret = 0
    for octet in struct.unpack("=" + "B" * len(octets), octets):
        ret = (ret << 8) + octet  # 左移 8 位，再加当前字节
    if not skip_assert:
        assert octets == I2OSP(ret, len(octets))  # 可选检查
    return ret


# 来自 draft-irtf-cfrg-hash-to-curve-07 草案
# hash_fn 应该是类似 hashlib.sha256 的固定输出哈希函数
#可扩展消息摘要输出长度固定，需要多轮哈希和 XOR 扩展才能达到指定长度
def expand_message_xmd(msg, dst, len_in_bytes, hash_fn, security_param, result_set=[]):
    # sanity checks and basic parameters
    b_in_bytes = hash_fn().digest_size
    r_in_bytes = hash_fn().block_size
    assert 8 * b_in_bytes >= 2 * security_param
    if len(dst) > 255:
        raise ValueError("dst len should be at most 255 bytes")

    # compute ell and check that sizes are as we expect
    ell = (len_in_bytes + b_in_bytes - 1) // b_in_bytes
    if ell > 255:
        raise ValueError("bad expand_message_xmd call: ell was %d" % ell)

    # compute prefix-free encoding of DST
    dst_prime = dst + I2OSP(len(dst), 1)
    assert len(dst_prime) == len(dst) + 1

    # padding and length strings
    Z_pad = I2OSP(0, r_in_bytes)
    l_i_b_str = I2OSP(len_in_bytes, 2)

    # compute blocks
    b_vals = [None] * ell
    msg_prime = Z_pad + _as_bytes(msg) + l_i_b_str + I2OSP(0, 1) + dst_prime
    b_0 = hash_fn(msg_prime).digest()
    b_vals[0] = hash_fn(b_0 + I2OSP(1, 1) + dst_prime).digest()
    for i in range(1, ell):
        b_vals[i] = hash_fn(_strxor(b_0, b_vals[i - 1]) + I2OSP(i + 1, 1) + dst_prime).digest()

    # assemble output
    uniform_bytes = (b'').join(b_vals)
    output = uniform_bytes[0 : len_in_bytes]

    vector = {
        "msg": msg,
        "len_in_bytes": "0x%x" % len_in_bytes,
        "k": "0x%x" % security_param,
        "DST_prime": to_hex(dst_prime),
        "msg_prime": to_hex(msg_prime),
        "uniform_bytes": to_hex(output),
    }
    result_set.append(vector)

    return output


# 来自 draft-irtf-cfrg-hash-to-curve-07 草案
# hash_fn 应该是类似 shake_128 的可变输出哈希函数（Python3 支持）
# 把原始消息扩展成更长的伪随机字节串。输出长度可任意指定，一次哈希就能得到目标长度的字节串（海绵函数）
def expand_message_xof(msg, dst, len_in_bytes, hash_fn, security_param, result_set=[]):
    if len(dst) > 255:
        raise ValueError("dst len should be at most 255 bytes")

    # compute prefix-free encoding of DST
    dst_prime = dst + I2OSP(len(dst), 1)
    assert len(dst_prime) == len(dst) + 1

    msg_prime = _as_bytes(msg) + I2OSP(len_in_bytes, 2) + dst_prime
    uniform_bytes = hash_fn(msg_prime).digest(len_in_bytes)

    vector = {
        "msg": msg,
        "len_in_bytes": "0x%x" % len_in_bytes,
        "k": "0x%x" % security_param,
        "DST_prime": to_hex(dst_prime),
        "msg_prime": to_hex(msg_prime),
        "uniform_bytes": to_hex(uniform_bytes),
    }
    result_set.append(vector)

    return uniform_bytes

#用途：作为“消息扩展器”的抽象基类，由上面的两个函数构成的
class Expander(object):
    def __init__(self, name, dst, dst_prime, hash_fn, security_param):
        self.name = name
        self._dst = dst_prime
        self.dst = dst
        self.hash_fn = hash_fn
        self.security_param = security_param
        self.test_vectors = []

    def expand_message(self, msg, len_in_bytes):
        raise Exception("Not implemented")

    def hash_name(self):
        name = self.hash_fn().name.upper()
        # Python incorrectly says SHAKE_128 rather than SHAKE128
        if name[:6] == "SHAKE_":
            name = "SHAKE" + name[6:]
        return name

    def __dict__(self):
        return {
            "name": self.name,
            "dst": to_hex(self.dst),
            "hash": self.hash_name(),
            "k": "0x%x" % self.security_param, #安全参数 k（比特数）
            "tests": json.dumps(self.test_vectors), #储测试向量，方便调试或验证
        }


#构造 expand_message_xmd 类
class XMDExpander(Expander):
    def __init__(self, dst, hash_fn, security_param):
        dst_prime = _as_bytes(dst)
        if len(dst_prime) > 255:
            # https://cfrg.github.io/draft-irtf-cfrg-hash-to-curve/draft-irtf-cfrg-hash-to-curve.html#name-using-dsts-longer-than-255-
            dst_prime = hash_fn(_as_bytes("H2C-OVERSIZE-DST-") + _as_bytes(dst)).digest()
        else:
            dst_prime = _as_bytes(dst)
        super(XMDExpander, self).__init__("expand_message_xmd", dst, dst_prime, hash_fn, security_param)

    def expand_message(self, msg, len_in_bytes):
        return expand_message_xmd(msg, self._dst, len_in_bytes, self.hash_fn, self.security_param, self.test_vectors)

#构造 expand_message_xof 类
class XOFExpander(Expander):
    def __init__(self, dst, hash_fn, security_param):
        dst_prime = _as_bytes(dst)
        if len(dst_prime) > 255:
            # https://cfrg.github.io/draft-irtf-cfrg-hash-to-curve/draft-irtf-cfrg-hash-to-curve.html#name-using-dsts-longer-than-255-
            dst_prime = hash_fn(_as_bytes("H2C-OVERSIZE-DST-") + _as_bytes(dst)).digest(math.ceil(2 * security_param / 8))
        super(XOFExpander, self).__init__("expand_message_xof", dst, dst_prime, hash_fn, security_param)

    def expand_message(self, msg, len_in_bytes):
        return expand_message_xof(msg, self._dst, len_in_bytes, self.hash_fn, self.security_param, self.test_vectors)



#通过上述两个扩展函数实现hash函数到域的扩展，将消息 msg 映射到一个或多个有限域元素
#输入是消息内容、向量个数count（映射到几个曲线上）、有限域模数、每个元素需要多少字节来表示blen、字节长度和扩展器
def hash_to_field(msg, count, modulus, degree, blen, expander):
    len_in_bytes = count * degree * blen # 计算所需的字节长度
    uniform_bytes = expander.expand_message(msg, len_in_bytes) #使用 expander 把消息映射为 固定长度的伪随机字节流
    u_vals = [None] * count # 初始化输出列表，每个元素是一个向量
    for i in range(0, count):   #外层循环 i：处理第 i 个向量
        e_vals = [None] * degree 
        for j in range(0, degree):
            elm_offset = blen * (j + i * degree)  # 定位当前元素在 uniform_bytes 中的位置
            tv = uniform_bytes[elm_offset : (elm_offset + blen)]  # 取出对应字节片段
            e_vals[j] = OS2IP(tv) % modulus  # OS2IP = Octets → Integer，把字节转换为整数并对模数取模，确保落在有限域 [0, modulus-1]
        u_vals[i] = e_vals  #形成该向量
    return u_vals
