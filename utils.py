import string, random, base64
from captcha.image import ImageCaptcha


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
