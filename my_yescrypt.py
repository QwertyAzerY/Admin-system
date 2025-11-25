from pyescrypt import Yescrypt, Mode

CRYPT_B64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
CRYPT_B64_INDEX = {c: i for i, c in enumerate(CRYPT_B64)}

def crypt_b64_encode(data: bytes) -> str:
    result = []
    i = 0
    while i < len(data):
        block = data[i:i+3]
        val = block[0]
        if len(block) > 1:
            val |= block[1] << 8
        if len(block) > 2:
            val |= block[2] << 16

        for _ in range(4):
            result.append(CRYPT_B64[val & 0x3f])
            val >>= 6

        i += 3

    return "".join(result)

def crypt_b64_decode(s: str) -> bytes:
    """
    Декодирует строку в формате Unix crypt-base64 (./0-9A-Za-z).
    Возвращает bytes.
    Padding нет, блоки идут без '='.
    """
    out = bytearray()
    i = 0
    length = len(s)

    while i < length:
        # читаем 4 символа = 24 бита = 3 байта
        chunk = s[i:i+4]
        val = 0
        shift = 0

        for ch in chunk:
            val |= CRYPT_B64_INDEX[ch] << shift
            shift += 6

        # извлекаем байты
        out.append(val & 0xff)
        out.append((val >> 8) & 0xff)
        out.append((val >> 16) & 0xff)

        i += 4

    return bytes(out)

def _yescrypt_hash(
        password,
        salt=None,
        block_count=2**12,
        block_size=32,
        time=0,
        **kwargs):
        
        return Yescrypt(
            mode=Mode.MCF,
            n=block_count,
            r=block_size,
            t=time,
        ).digest(
            password.encode(),
            salt=salt
        ).decode()

def hash_password(password:str, salt:bytes):
    try:
        hash=_yescrypt_hash(password=password, salt=salt)
    except Exception as E:
        return False, f'Exception during hash function {E}'
    return True, hash