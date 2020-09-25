import string, random, base64, os
from captcha.image import ImageCaptcha
import struct
import time
import hmac
import hashlib
import base64
from Crypto.Cipher import DES
from Crypto import Random
import pickle

KEY = '12345678'


def generate_captcha_string(N):
    """
    :return: random N character alphanumeric string
    """
    res = ''.join(random.choices(string.ascii_uppercase +  string.digits, k = N))
    return res


def generate_captcha_image(capta_string):
    """
    :return: a  base64 encoded byte object containg image which
    can be used in RESTAPI. Size around 24kb for a 8 character image
    show in UI example:
    https://stackoverflow.com/questions/42395034/how-to-display-binary-data-as-image-in-react
    """
    image = ImageCaptcha()  # can add your custom images in a dir here too [see captcha docs: pypi]
    data = image.generate(capta_string)
    return base64.b64encode(data.getvalue())


def validate_captcha(user_input, captcha_string):
    return user_input.strip() == captcha_string


def encryptData(data, key):
    """
    iv - intial feedback value
    convert to latin1 encoding for storing in mongodb (mongo is utf8 storage database), therefore we need to
    pickle and decode to latin1( one to one mapping with utf-8)
    """
    pickle_str_flag = '@$xy*@!h'
    iv = Random.get_random_bytes(8)
    des = DES.new(key, DES.MODE_CFB, iv)
    data = data.encode('utf-8')
    cipher_text = des.encrypt(data)
    # now add the iv in the cipher_text
    str_to_store = iv + cipher_text
    new_data = pickle_str_flag + str_to_store
    new_data = new_data.decode('latin-1')
    new_data = new_data.encode('utf-8')
    return new_data


def decryptData(cipher_text, key):
    # first get the iv from the cipher_text
    """
    decrypts the encrypted data. get the iv first which is the part of string stored in the database
    """
    try:
        # Strings which starts with pickle_str_flag was added later to fix the pickle security issues RCE
        # This condition is needed to support strings which were encrypted earlier using pickle
        pickle_str_flag = '@$xy*@!h'
        cipher_text = cipher_text.decode('utf-8') if isinstance(cipher_text, str) else cipher_text
        cipher_text = cipher_text.encode('latin-1')
        if cipher_text.startswith(pickle_str_flag):
            cipher_text = cipher_text.replace(pickle_str_flag, '')
        else:
            black_list = ["shell", "bin", "system", "ngrok", "sys", "bash", "sudo", "mongo", "mknod"]
            for each_risk in black_list:
                if each_risk in cipher_text:
                    raise Exception("Danger, blacklisted keys found in secret")
            cipher_text = pickle.loads(cipher_text)
        iv = cipher_text[0:8]
        des = DES.new(key, DES.MODE_CFB, iv)
        data = des.decrypt(cipher_text[8:])
        data = data.decode('utf-8')
        return str(data)
    except EOFError:
        """
        error will come for empty passwords or usernames or empy strings
        """
        return cipher_text


def get_new_secret_ket():
    return encryptData(base64.b32encode(os.urandom(10)), KEY)


def mfa_authenticate(secret, token):
    """
    Witty people will use pyotp, babies who are just learning, use this function
    token: the token input by the user
    secret: the secret seed generated per user for token generation
    OTP generation using HMAC SHA1 algorithm and rfc https://tools.ietf.org/html/rfc6238
    """

    if not secret:
        return False

    tm = int(time.time() / 30)
    secretkey = base64.b32decode(secret)

    # 30 seconds behind and ahead
    for td in [-1, 0, 1]:

        # convert timestamp to bytes
        b = struct.pack(">q", tm + td)

        # generate HMAC-SHA1 from timestamp with the given secret
        hm = hmac.HMAC(secretkey, b, hashlib.sha1).digest()

        # extract 4 bytes from digest based on LSB (assuming little-endian)
        offset = ord(hm[-1]) & 0x0F
        thash = hm[offset:offset+4]

        # get code
        code = struct.unpack(">L", thash)[0]
        code &= 0x7FFFFFFF # mask out first two bytes
        code %= 1000000    # reminder

        if ("%06d" % code) == str(token):
            return True

    return False

