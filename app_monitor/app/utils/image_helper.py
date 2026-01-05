import base64

def bytes_to_base64(data: bytes) -> str:
    """将二进制数据转换为 Base64 字符串"""
    if not data:
        return None
    try:
        return base64.b64encode(data).decode('utf-8')
    except Exception:
        return None