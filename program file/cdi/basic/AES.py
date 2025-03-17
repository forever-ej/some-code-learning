from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2


# 加密函数
def encrypt_password(password, key):
    # 使用给定的key生成一个随机的16字节（即128位）的初始化向量（IV）
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    encrypted_password = cipher.encrypt(password.encode('utf-8'))
    # 返回IV与加密后的数据，二者都是必要的以供解密使用
    return iv + encrypted_password


# 解密函数
def decrypt_password(encrypted_data, key):
    # 从加密数据的前16字节提取IV
    iv = encrypted_data[:16]
    # 实际的加密数据是剩余的部分
    encrypted_password = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    decrypted_password = cipher.decrypt(encrypted_password).decode('utf-8')
    return decrypted_password


# 主函数演示加密解密过程
if __name__ == '__main__':
    # 假设这是用户的密码
    user_password = 'MySecurePassword123!'

    # 使用PBKDF2从一个口令生成一个加密用的key，这里只是为了演示简化处理
    # 在实际应用中，你应该使用更复杂的口令和更多的迭代次数
    encryption_key = PBKDF2("YourSecretKeyForEncryption", b'salt_', dkLen=32)

    print("原始密码:", user_password)

    # 加密密码
    encrypted_data = encrypt_password(user_password, encryption_key)
    print("加密后的数据:", encrypted_data.hex())

    # 解密密码
    decrypted_password = decrypt_password(encrypted_data, encryption_key)
    print("解密后的密码:", decrypted_password)