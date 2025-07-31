import argparse, os, traceback
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
from chiperx.crypt import (
    encrypt_file, decrypt_file,
    EncryptionError, DecryptionError,
    encrypt_data, decrypt_data
)
global output_file

def parse_pattern_file(pattern_file: str) -> tuple[str, list[str]]:
    if not os.path.isfile(pattern_file):
        raise FileNotFoundError(f"Pattern file not found: {pattern_file}")
    with open(pattern_file, 'r') as f:
        line = f.readline().strip()
        if ':' not in line:
            raise ValueError("Invalid pattern format. Use: key:AXXA")
        key, pattern = line.split(':', 1)
        return key, list(pattern.upper())

def encrypt_with_pattern(data: bytes, pattern: list[str], key: str) -> bytes:
    for method in pattern:
        if method == 'A':
            data = encrypt_data('aes', data, key)
        elif method == 'X':
            data = encrypt_data('xor', data, key)
        elif method == 'V':
            data = encrypt_data('vigenere', data, key)
        elif method == 'R':
            data = encrypt_data('rc4', data, key)
        elif method == 'C':
            data = encrypt_data('vichaos', data, key)
        elif method == 'S':
            data = encrypt_data('vichaos_secure', data, key)
        else:
            raise EncryptionError(f"Unknown pattern method: {method}")
    return data

def decrypt_with_pattern(data: bytes, pattern: list[str], key: str) -> bytes:
    for method in reversed(pattern):
        if method == 'A':
            data = decrypt_data('aes', data, key)
        elif method == 'X':
            data = decrypt_data('xor', data, key)
        elif method == 'V':
            data = decrypt_data('vigenere', data, key)
        elif method == 'R':
            data = decrypt_data('rc4', data, key)
        elif method == 'C':
            data = decrypt_data('vichaos', data, key)
        elif method == 'S':
            data = decrypt_data('vichaos_secure', data, key)
        else:
            raise DecryptionError(f"Unknown pattern method: {method}")
    return data

def process_directory(input_dir: str, key: str, pattern: list[str] = None, method: str = None, mode: str = "encrypt"):
    output_root = os.path.abspath(input_dir)
    for root, _, files in os.walk(input_dir):
        for file in files:
            in_path = os.path.join(root, file)
            rel_path = os.path.relpath(in_path, input_dir)
            out_path = os.path.join(output_root, rel_path)

            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(in_path, 'rb') as f:
                data = f.read()
            try:
                if pattern:
                    if mode == "encrypt":
                        result = encrypt_with_pattern(data, pattern, key)
                    else:
                        result = decrypt_with_pattern(data, pattern, key)
                else:
                    if mode == "encrypt":
                        result = encrypt_data(method, data, key)
                    else:
                        result = decrypt_data(method, data, key)
                with open(out_path, 'wb') as f:
                    f.write(result)
                print(f"{mode.title()}ed: {in_path} -> {out_path}")
            except Exception as e:
                print(f"Failed to process {in_path}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Chiper-X: file encrypter/decrypter using XOR, AES, Vigenère, RC4, ViChaos, or ViChaos Secure.")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], nargs='?', help="Mode: encrypt or decrypt")
    parser.add_argument("input", nargs='?', help="Input file or directory")
    parser.add_argument("output", nargs='?', help="Output file (for single file only)")
    parser.add_argument("--key", help="Encryption key (string)")
    parser.add_argument("--method", choices=["xor", "aes", "vigenere", "rc4", "vichaos", "vichaos_secure"], help="Encryption method")
    parser.add_argument("--pattern", help="Pattern file path (e.g., chiper-x.pattern)")
    parser.add_argument("--gui", action="store_true", help="Show Chiper-X GUI")

    args = parser.parse_args()

    if args.gui:

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

                # Output (will be hidden for directory input)
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
                self.method_var = tk.StringVar()
                self.method_menu = tk.OptionMenu(self, self.method_var, "xor", "aes", "vigenere", "rc4", "vichaos", "vichaos_secure")
                self.method_menu.grid(row=4, column=1, sticky="ew", padx=8)
                self.method_menu.config(width=16)

                # Pattern
                tk.Label(self, text="Pattern file:").grid(row=5, column=0, sticky="w", padx=8)
                self.pattern_entry = tk.Entry(self)
                self.pattern_entry.grid(row=5, column=1, sticky="ew", padx=8)
                tk.Button(self, text="Browse", command=self.browse_pattern).grid(row=5, column=2, padx=4)

                # Run button
                run_btn = tk.Button(self, text="Run", command=self.run_chiperx, width=16, bg="#4CAF50", fg="white")
                run_btn.grid(row=6, column=1, pady=18, sticky="ew")

                # Make window resize responsive
                for i in range(7):
                    self.grid_rowconfigure(i, weight=1)
                self.grid_columnconfigure(1, weight=1)

                # Bind input entry change to check if it's a directory
                self.input_entry.bind("<FocusOut>", self.check_input_type)
                self.input_entry.bind("<KeyRelease>", self.check_input_type)

                # Bind pattern entry change to hide/show key and method
                self.pattern_entry.bind("<FocusOut>", self.check_pattern_selected)
                self.pattern_entry.bind("<KeyRelease>", self.check_pattern_selected)

            def browse_input(self):
                # Use askopenfilename first, if cancelled, then askdirectory
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
                        output_file = output_path if output_path else input_path  # output file default to input file

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

        ChiperXGUI().mainloop()
        return

    try:
        if args.input is not None and os.path.isdir(args.input):
            if args.pattern:
                key, pattern = parse_pattern_file(args.pattern)
                process_directory(args.input, key, pattern=pattern, mode=args.mode)
            else:
                if not args.key or not args.method:
                    raise ValueError("If --pattern not used, --key and --method are required")
                process_directory(args.input, args.key, method=args.method, mode=args.mode)
            print(f"{args.mode.title()}ion complete for directory: {args.input}")
            return

        # File tunggal
        if args.input is None:
            parser.print_help()
            print("\nError: Input file or directory required")
            return 1

        with open(args.input, 'rb') as f:
            data = f.read()
        output_file = args.output if args.output else args.input
        
        if args.pattern:
            key, pattern = parse_pattern_file(args.pattern)
            if args.mode == "encrypt":
                result = encrypt_with_pattern(data, pattern, key)
            else:
                result = decrypt_with_pattern(data, pattern, key)
            with open(output_file, 'wb') as f:
                f.write(result)
        else:
            if not args.key or not args.method:
                raise ValueError("If --pattern not used, --key and --method are required")
            
            if args.mode == "encrypt":
                encrypt_file(args.method, args.input, output_file, args.key)
            else:
                decrypt_file(args.method, args.input, output_file, args.key)
                
        print(f"{args.mode.title()}ion complete: {output_file}")

    except (EncryptionError, DecryptionError, Exception, ValueError) as e:
        print(f"Error: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    main()