import tkinter as tk
from tkinter import messagebox

def xor(a, b):
    return a ^ b

def hash_function(message):
    h = 0xFFFFFFFFFFFFFFFF 
    block_size = 8 
    message_bytes = message.encode('utf-8')

    for i in range(0, len(message_bytes), block_size):
        block = message_bytes[i:i + block_size]
        block_value = 0
        for byte in block:
            block_value = (block_value << 8) | byte
        h = xor(h, block_value)
    return hex(h)

def on_hash_button_click():
    message = input_text.get("1.0", "end-1c").strip()
    if not message:
        messagebox.showerror("Ошибка", "Введите сообщение.")
        return
    hashed_message = hash_function(message)
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, hashed_message)

def on_verify_button_click():
    message = input_text.get("1.0", "end-1c").strip()
    hashed_message = output_text.get("1.0", tk.END).strip()
    if not message or not hashed_message:
        messagebox.showerror("Ошибка", "Введите сообщение и вычислите хэш.")
        return

    new_hash = hash_function(message)
    if new_hash == hashed_message:
        messagebox.showinfo("Результат", "Хеш верный!")
    else:
        messagebox.showerror("Ошибка", "Хеш неверный!")

root = tk.Tk()
root.title("Хэш-функция с проверкой")
root.geometry("400x350")

input_text = tk.Text(root, height=5, width=40)
input_text.pack(pady=10)

hash_button = tk.Button(root, text="Вычислить хэш", command=on_hash_button_click)
hash_button.pack(pady=5)

output_text = tk.Text(root, height=2, width=40)
output_text.pack(pady=10)

verify_button = tk.Button(root, text="Проверить хэш", command=on_verify_button_click)
verify_button.pack(pady=10)

root.mainloop()

