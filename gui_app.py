# gui_app.py
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from sender_logic import send_file_logic
from receiver_logic import start_receiver_logic
import threading

class App:
    def __init__(self, root):
        self.root = root
        root.title("Güvenli Dosya Transferi")

        self.main_frame = tk.Frame(root, padx=10, pady=10)
        self.main_frame.pack()

        self.sender_button = tk.Button(self.main_frame, text="Dosya Gönder", command=self.open_sender_window)
        self.sender_button.pack(pady=5)

        self.receiver_button = tk.Button(self.main_frame, text="Dosya Al", command=self.open_receiver_window)
        self.receiver_button.pack(pady=5)

    def open_sender_window(self):
        SenderWindow(tk.Toplevel(self.root))

    def open_receiver_window(self):
        ReceiverWindow(tk.Toplevel(self.root))

class SenderWindow:
    def __init__(self, root):
        self.root = root
        root.title("Gönderici")
        self.file_path = ""

        self.frame = tk.Frame(root, padx=10, pady=10)
        self.frame.pack()

        self.select_button = tk.Button(self.frame, text="Dosya Seç", command=self.select_file)
        self.select_button.pack(pady=5)

        self.path_label = tk.Label(self.frame, text="Henüz dosya seçilmedi.")
        self.path_label.pack(pady=5)

        self.send_button = tk.Button(self.frame, text="Gönder", command=self.send, state=tk.DISABLED)
        self.send_button.pack(pady=5)
        
        self.status_area = scrolledtext.ScrolledText(self.frame, width=60, height=15)
        self.status_area.pack(pady=10)
        self.status_area.configure(state='disabled')

    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.path_label.config(text=self.file_path)
            self.send_button.config(state=tk.NORMAL)
    
    def update_status(self, message):
        self.status_area.configure(state='normal')
        self.status_area.insert(tk.END, message + '\n')
        self.status_area.configure(state='disabled')
        self.status_area.see(tk.END)

    def send(self):
        if not self.file_path:
            messagebox.showerror("Hata", "Lütfen önce bir dosya seçin!")
            return
        
        self.send_button.config(state=tk.DISABLED)
        # Ağ işlemini ayrı bir thread'de çalıştırarak arayüzün donmasını engelle
        thread = threading.Thread(target=send_file_logic, args=(self.file_path, self.update_status))
        thread.daemon = True
        thread.start()

class ReceiverWindow:
    def __init__(self, root):
        self.root = root
        root.title("Alıcı")

        self.frame = tk.Frame(root, padx=10, pady=10)
        self.frame.pack()

        self.start_button = tk.Button(self.frame, text="Dinlemeyi Başlat", command=self.start_listening)
        self.start_button.pack(pady=5)

        self.status_area = scrolledtext.ScrolledText(self.frame, width=60, height=15)
        self.status_area.pack(pady=10)
        self.status_area.configure(state='disabled')
    
    def update_status(self, message):
        self.status_area.configure(state='normal')
        self.status_area.insert(tk.END, message + '\n')
        self.status_area.configure(state='disabled')
        self.status_area.see(tk.END)

    def start_listening(self):
        self.start_button.config(state=tk.DISABLED)
        thread = threading.Thread(target=start_receiver_logic, args=(self.update_status,))
        thread.daemon = True
        thread.start()

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()