import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox
from chiper_x import (
    encrypt_file, decrypt_file,
    encrypt_with_pattern, decrypt_with_pattern,
    process_directory, parse_pattern_file
)

class ProgressDialog(tk.Toplevel):
    def __init__(self, parent, title="Processing...", message="Please wait..."):
        super().__init__(parent)
        self.title(title)
        self.geometry("320x100")
        self.resizable(False, False)
        self.grab_set()
        self.label = tk.Label(self, text=message, font=("Arial", 12))
        self.label.pack(pady=24)
        self.update_idletasks()

class ChiperXGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Chiper-X GUI")
        self.configure(padx=16, pady=16)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(6, weight=1)

        # Mode
        tk.Label(self, text="Mode:").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        self.mode_var = tk.StringVar(value="encrypt")
        mode_menu = tk.OptionMenu(self, self.mode_var, "encrypt", "decrypt")
        mode_menu.grid(row=0, column=1, sticky="ew", padx=8)
        mode_menu.config(width=16)

        # Input
        tk.Label(self, text="Input file/dir:").grid(row=1, column=0, sticky="w", padx=8)
        self.input_entry = tk.Entry(self)
        self.input_entry.grid(row=1, column=1, sticky="ew", padx=8)
        tk.Button(self, text="Browse", command=self.browse_input).grid(row=1, column=2, padx=4)

        # Output
        self.output_label = tk.Label(self, text="Output file:")
        self.output_label.grid(row=2, column=0, sticky="w", padx=8)
        self.output_entry = tk.Entry(self)
        self.output_entry.grid(row=2, column=1, sticky="ew", padx=8)
        self.output_browse_btn = tk.Button(self, text="Browse", command=self.browse_output)
        self.output_browse_btn.grid(row=2, column=2, padx=4)

        # Key
        self.key_label = tk.Label(self, text="Key:")
        self.key_label.grid(row=3, column=0, sticky="w", padx=8)
        self.key_entry = tk.Entry(self)
        self.key_entry.grid(row=3, column=1, sticky="ew", padx=8)

        # Method
        self.method_label = tk.Label(self, text="Method:")
        self.method_label.grid(row=4, column=0, sticky="w", padx=8)
        self.method_var = tk.StringVar(value="vichaos_secure")
        self.method_menu = tk.OptionMenu(self, self.method_var, "xor", "aes", "vigenere", "rc4", "vichaos", "vichaos_secure")
        self.method_menu.grid(row=4, column=1, sticky="ew", padx=8)
        self.method_menu.config(width=16)

        # Pattern
        tk.Label(self, text="Pattern file:").grid(row=5, column=0, sticky="w", padx=8)
        self.pattern_entry = tk.Entry(self)
        self.pattern_entry.grid(row=5, column=1, sticky="ew", padx=8)
        tk.Button(self, text="Browse", command=self.browse_pattern).grid(row=5, column=2, padx=4)

        # Run
        run_btn = tk.Button(self, text="Run", command=self.run_chiperx, width=16, bg="#4CAF50", fg="white")
        run_btn.grid(row=6, column=1, pady=18, sticky="ew")

        # Resize
        for i in range(7):
            self.grid_rowconfigure(i, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Bindings
        self.input_entry.bind("<FocusOut>", self.check_input_type)
        self.input_entry.bind("<KeyRelease>", self.check_input_type)
        self.pattern_entry.bind("<FocusOut>", self.check_pattern_selected)
        self.pattern_entry.bind("<KeyRelease>", self.check_pattern_selected)

    def browse_input(self):
        path = filedialog.askopenfilename()
        if not path:
            path = filedialog.askdirectory()
        if path:
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, path)
            self.check_input_type()

    def browse_output(self):
        path = filedialog.asksaveasfilename()
        if path:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, path)

    def browse_pattern(self):
        path = filedialog.askopenfilename(filetypes=[("Pattern Files", "*.pattern"), ("All Files", "*.*")])
        if path:
            self.pattern_entry.delete(0, tk.END)
            self.pattern_entry.insert(0, path)
            self.check_pattern_selected()

    def check_input_type(self, event=None):
        input_path = self.input_entry.get()
        if os.path.isdir(input_path) and input_path:
            self.output_entry.grid_remove()
            self.output_browse_btn.grid_remove()
            self.output_label.grid_remove()
        else:
            self.output_entry.grid()
            self.output_browse_btn.grid()
            self.output_label.grid()

    def check_pattern_selected(self, event=None):
        pattern_path = self.pattern_entry.get()
        if pattern_path.strip():
            self.key_label.grid_remove()
            self.key_entry.grid_remove()
            self.method_label.grid_remove()
            self.method_menu.grid_remove()
        else:
            self.key_label.grid()
            self.key_entry.grid()
            self.method_label.grid()
            self.method_menu.grid()

    def run_chiperx(self):
        mode = self.mode_var.get()
        input_path = self.input_entry.get()
        output_path = self.output_entry.get()
        key = self.key_entry.get()
        method = self.method_var.get()
        pattern_path = self.pattern_entry.get()

        def process():
            try:
                if not input_path:
                    raise ValueError("Input file/directory required")
                if os.path.isdir(input_path):
                    if pattern_path:
                        key_, pattern = parse_pattern_file(pattern_path)
                        process_directory(input_path, key_, pattern=pattern, mode=mode)
                    else:
                        if not key or not method:
                            raise ValueError("If pattern not used, key and method are required")
                        process_directory(input_path, key, method=method, mode=mode)
                    self.after(0, lambda: messagebox.showinfo("Success", f"{mode.title()}ion complete for directory: {input_path}"))
                    self.after(0, progress.destroy)
                    return

                with open(input_path, 'rb') as f:
                    data = f.read()
                output_file = output_path if output_path else input_path

                if pattern_path:
                    key_, pattern = parse_pattern_file(pattern_path)
                    if mode == "encrypt":
                        result = encrypt_with_pattern(data, pattern, key_)
                    else:
                        result = decrypt_with_pattern(data, pattern, key_)
                    with open(output_file, 'wb') as f:
                        f.write(result)
                else:
                    if not key or not method:
                        raise ValueError("If pattern not used, key and method are required")
                    if mode == "encrypt":
                        encrypt_file(method, input_path, output_file, key)
                    else:
                        decrypt_file(method, input_path, output_file, key)
                self.after(0, lambda: messagebox.showinfo("Success", f"{mode.title()}ion complete: {output_file}"))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                self.after(0, progress.destroy)

        progress = ProgressDialog(self, message="Processing, please wait...")
        threading.Thread(target=process, daemon=True).start()
