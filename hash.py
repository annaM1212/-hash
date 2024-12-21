import tkinter as tk
from tkinter import messagebox

S_BOXES = [
    [0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5],
    [0x3, 0x7, 0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1],
    [0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7, 0x1, 0x9],
    [0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6],
    [0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6],
    [0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5, 0x9, 0x4, 0x8, 0xF, 0xE, 0x6],
    [0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3, 0xB, 0xE],
    [0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7, 0xD, 0x4]
]


def substitute(value):
    result = 0
    for i in range(8):
        nibble = (value >> (4 * i)) & 0xF
        result |= S_BOXES[i][nibble] << (4 * i)
    return result


def rotate_left(value, shift, size=32):
    return ((value << shift) | (value >> (size - shift))) & ((1 << size) - 1)


def f(block, key):
    temp = (block + key) % (2 ** 32)
    substituted = substitute(temp)
    return rotate_left(substituted, 11)


def generate_keys(master_key):
    key_parts = [(master_key >> (32 * i)) & 0xFFFFFFFF for i in range(8)]
    return key_parts


def encrypt_block(left, right, keys):
    for i in range(16):
        round_key = keys[i % 8]
        temp = f(right, round_key)
        left, right = right, left ^ temp
    return right, left


def gost_encrypt(message, key, M_i):
    master_key = int.from_bytes(key, 'big')
    keys = generate_keys(master_key)

    if len(message) % 8 != 0:
        message += b'\x00' * (8 - len(message) % 8)

    encrypted = []

    for i in range(0, len(message), 8):
        block = message[i:i + 8]
        left = int.from_bytes(block[:4], 'big')
        right = int.from_bytes(block[4:], 'big')

        left, right = encrypt_block(left, right, keys)

        encrypted_block = (left.to_bytes(4, 'big') + right.to_bytes(4, 'big'))
        encrypted_block_int = int.from_bytes(encrypted_block, 'big') ^ M_i

        encrypted.append(encrypted_block_int.to_bytes(8, 'big'))

    encrypted_result = b''.join(encrypted)
    return encrypted_result.hex()


def gost_hash(message, key):
    H = 0
    message_blocks = [message[i:i + 8] for i in range(0, len(message), 8)]

    for M in message_blocks:
        H = int(H)
        M_i = int.from_bytes(M.ljust(8, b'\x00'), 'big')
        # H(i) = E(H(i-1))(M(i)) ⊕ M(i)
        encrypted_H = gost_encrypt(H.to_bytes(8, 'big'), key, M_i) # H(i) = E(H(i-1))(M(i))
        H = int(encrypted_H, 16) ^ M_i  # H(i) = E(H(i-1))(M(i)) ⊕ M(i)

    return H.to_bytes(8, 'big').hex()


def calculate_hash():
    message = text_input.get("1.0", tk.END).strip()
    key = key_input.get().encode('utf-8')
    if len(key) != 8:
        messagebox.showerror("Ошибка", "Ключ должен быть ровно 8 байт.")
        return
    hash_value = gost_hash(message.encode('utf-8'), key)
    result_label.config(text=f"Хэш: {hash_value}")


app = tk.Tk()
app.title("GOST Хэш-Алгоритм")

text_input = tk.Text(app, height=10, width=50)
text_input.pack(pady=10)

key_input = tk.Entry(app, width=50)
key_input.pack(pady=10)
key_input.insert(0, "Введите 8-байтный ключ")

calculate_button = tk.Button(app, text="Вычислить Хэш", command=calculate_hash)
calculate_button.pack(pady=10)

result_label = tk.Label(app, text="")
result_label.pack(pady=10)

app.mainloop()
