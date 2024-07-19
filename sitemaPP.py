import os
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from datetime import datetime
import xml.etree.ElementTree as ET
import json
import csv
import hashlib

class AdvancedSitemapGenerator(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Sitemap Generator")
        self.geometry("1200x800")
        self.configure(bg="#f0f0f0")

        self.path_var = tk.StringVar()
        self.depth_var = tk.IntVar(value=100)
        self.show_size_var = tk.BooleanVar(value=True)
        self.show_date_var = tk.BooleanVar(value=True)
        self.dark_mode_var = tk.BooleanVar(value=False)
        
        self.excluded_paths = []
        self.file_types = set()
        self.included_types = set()
        self.excluded_types = set()
        
        self.sitemap_data = []
        self.duplicate_files = {}

        self.create_widgets()
        self.apply_theme()

    def create_widgets(self):
        style = ttk.Style(self)
        style.theme_use('clam')

        main_frame = ttk.Frame(self, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Directory selection
        path_frame = ttk.Frame(left_frame)
        path_frame.pack(fill=tk.X, pady=(0, 20))
        ttk.Label(path_frame, text="Directory Path:", font=("Helvetica", 12)).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Entry(path_frame, textvariable=self.path_var, width=50, font=("Helvetica", 12)).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(path_frame, text="Browse", command=self.browse_directory, style="Accent.TButton").pack(side=tk.LEFT)

        # Options
        options_frame = ttk.LabelFrame(left_frame, text="Options", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Label(options_frame, text="Max Depth:", font=("Helvetica", 12)).grid(row=0, column=0, sticky="w", padx=(0, 10), pady=5)
        depth_spinbox = ttk.Spinbox(options_frame, from_=1, to=100, textvariable=self.depth_var, width=5, font=("Helvetica", 12))
        depth_spinbox.grid(row=0, column=1, sticky="w", padx=(0, 20), pady=5)
        depth_spinbox.bind("<FocusOut>", lambda e: self.depth_var.set(max(1, min(100, int(self.depth_var.get())))))

        ttk.Checkbutton(options_frame, text="Show File Sizes", variable=self.show_size_var, style="Toggle.TCheckbutton").grid(row=0, column=2, sticky="w", padx=(0, 20), pady=5)
        ttk.Checkbutton(options_frame, text="Show Dates", variable=self.show_date_var, style="Toggle.TCheckbutton").grid(row=0, column=3, sticky="w", pady=5)

        # File type filtering
        file_type_frame = ttk.LabelFrame(left_frame, text="File Type Filtering", padding="10")
        file_type_frame.pack(fill=tk.X, pady=(0, 20))

        self.file_type_listbox = tk.Listbox(file_type_frame, selectmode=tk.MULTIPLE, height=5, font=("Helvetica", 12))
        self.file_type_listbox.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        file_type_buttons_frame = ttk.Frame(file_type_frame)
        file_type_buttons_frame.pack(side=tk.LEFT)
        ttk.Button(file_type_buttons_frame, text="Include", command=self.include_file_types, style="Accent.TButton").pack(pady=(0, 5))
        ttk.Button(file_type_buttons_frame, text="Exclude", command=self.exclude_file_types, style="Accent.TButton").pack()

        # Excluded paths
        excluded_frame = ttk.LabelFrame(left_frame, text="Excluded Paths", padding="10")
        excluded_frame.pack(fill=tk.X, pady=(0, 20))

        self.excluded_listbox = tk.Listbox(excluded_frame, height=3, font=("Helvetica", 12))
        self.excluded_listbox.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        exclude_buttons_frame = ttk.Frame(excluded_frame)
        exclude_buttons_frame.pack(side=tk.LEFT)
        ttk.Button(exclude_buttons_frame, text="Add", command=self.add_excluded_path, style="Accent.TButton").pack(pady=(0, 5))
        ttk.Button(exclude_buttons_frame, text="Remove", command=self.remove_excluded_path, style="Accent.TButton").pack()

        # Action buttons
        button_frame = ttk.Frame(left_frame)
        button_frame.pack(fill=tk.X, pady=(0, 20))

        ttk.Button(button_frame, text="Generate Sitemap", command=self.generate_sitemap, style="Accent.TButton").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Save as Text", command=lambda: self.save_sitemap("txt")).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Save as XML", command=lambda: self.save_sitemap("xml")).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Save as JSON", command=lambda: self.save_sitemap("json")).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Save as CSV", command=lambda: self.save_sitemap("csv")).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Copy Sitemap", command=self.copy_sitemap).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Checkbutton(button_frame, text="Dark Mode", variable=self.dark_mode_var, command=self.apply_theme, style="Toggle.TCheckbutton").pack(side=tk.RIGHT)

        # Tree view
        self.tree = ttk.Treeview(right_frame)

        self.tree.pack(expand=True, fill=tk.BOTH)

        # Sitemap display
        self.sitemap_text = scrolledtext.ScrolledText(left_frame, wrap=tk.WORD, width=70, height=20, font=("Helvetica", 12))
        self.sitemap_text.pack(expand=True, fill=tk.BOTH, pady=(0, 20))

        # Search
        search_frame = ttk.Frame(left_frame)
        search_frame.pack(fill=tk.X)
        self.search_var = tk.StringVar()
        ttk.Entry(search_frame, textvariable=self.search_var, width=30, font=("Helvetica", 12)).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(search_frame, text="Search", command=self.search_sitemap, style="Accent.TButton").pack(side=tk.LEFT)

        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(left_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(20, 0))

    def apply_theme(self):
        style = ttk.Style()
        if self.dark_mode_var.get():
            self.configure(bg="#2c2c2c")
            style.configure("TFrame", background="#2c2c2c")
            style.configure("TLabel", background="#2c2c2c", foreground="#ffffff")
            style.configure("TLabelframe", background="#2c2c2c", foreground="#ffffff")
            style.configure("TLabelframe.Label", background="#2c2c2c", foreground="#ffffff")
            style.configure("TCheckbutton", background="#2c2c2c", foreground="#ffffff")
            style.configure("TButton", background="#4a4a4a", foreground="#ffffff")
            style.configure("Accent.TButton", background="#0080ff", foreground="#ffffff")
            style.configure("Toggle.TCheckbutton", background="#2c2c2c", foreground="#ffffff")
            self.sitemap_text.config(bg="#3c3c3c", fg="#ffffff", insertbackground="#ffffff")
            self.excluded_listbox.config(bg="#3c3c3c", fg="#ffffff")
            self.file_type_listbox.config(bg="#3c3c3c", fg="#ffffff")
            self.tree.configure(style="Dark.Treeview")
            style.configure("Dark.Treeview", background="#3c3c3c", foreground="#ffffff", fieldbackground="#3c3c3c")
        else:
            self.configure(bg="#f0f0f0")
            style.configure("TFrame", background="#f0f0f0")
            style.configure("TLabel", background="#f0f0f0", foreground="#000000")
            style.configure("TLabelframe", background="#f0f0f0", foreground="#000000")
            style.configure("TLabelframe.Label", background="#f0f0f0", foreground="#000000")
            style.configure("TCheckbutton", background="#f0f0f0", foreground="#000000")
            style.configure("TButton", background="#e0e0e0", foreground="#000000")
            style.configure("Accent.TButton", background="#0080ff", foreground="#ffffff")
            style.configure("Toggle.TCheckbutton", background="#f0f0f0", foreground="#000000")
            self.sitemap_text.config(bg="#ffffff", fg="#000000", insertbackground="#000000")
            self.excluded_listbox.config(bg="#ffffff", fg="#000000")
            self.file_type_listbox.config(bg="#ffffff", fg="#000000")
            self.tree.configure(style="Light.Treeview")
            style.configure("Light.Treeview", background="#ffffff", foreground="#000000", fieldbackground="#ffffff")

        style.configure("TButton", padding=10, font=("Helvetica", 12))
        style.configure("Accent.TButton", padding=10, font=("Helvetica", 12, "bold"))
        style.configure("Toggle.TCheckbutton", font=("Helvetica", 12))

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.path_var.set(directory)
            self.scan_file_types(directory)

    def scan_file_types(self, directory):
        self.file_types.clear()
        for root, _, files in os.walk(directory):
            for file in files:
                _, ext = os.path.splitext(file)
                if ext:
                    self.file_types.add(ext.lower())
        self.update_file_type_listbox()

    def update_file_type_listbox(self):
        self.file_type_listbox.delete(0, tk.END)
        for file_type in sorted(self.file_types):
            self.file_type_listbox.insert(tk.END, file_type)
            if file_type in self.included_types:
                self.file_type_listbox.itemconfig(tk.END, {'bg': 'lightgreen'})
            elif file_type in self.excluded_types:
                self.file_type_listbox.itemconfig(tk.END, {'bg': 'lightcoral'})

    def include_file_types(self):
        selected = [self.file_type_listbox.get(i) for i in self.file_type_listbox.curselection()]
        self.included_types.update(selected)
        self.excluded_types.difference_update(selected)
        self.update_file_type_listbox()

    def exclude_file_types(self):
        selected = [self.file_type_listbox.get(i) for i in self.file_type_listbox.curselection()]
        self.excluded_types.update(selected)
        self.included_types.difference_update(selected)
        self.update_file_type_listbox()

    def add_excluded_path(self):
        path = filedialog.askdirectory()
        if path and path not in self.excluded_paths:
            self.excluded_paths.append(path)
            self.excluded_listbox.insert(tk.END, path)

    def remove_excluded_path(self):
        selection = self.excluded_listbox.curselection()
        if selection:
            index = selection[0]
            path = self.excluded_listbox.get(index)
            self.excluded_paths.remove(path)
            self.excluded_listbox.delete(index)

    def generate_sitemap(self):
        directory = self.path_var.get()
        if directory and os.path.isdir(directory):
            self.sitemap_text.delete(1.0, tk.END)
            self.tree.delete(*self.tree.get_children())
            self.sitemap_data.clear()
            self.duplicate_files.clear()
            sitemap = self.get_sitemap(directory)
            self.sitemap_text.insert(tk.END, sitemap)
            self.populate_tree()
            self.show_duplicate_files()
        else:
            self.sitemap_text.delete(1.0, tk.END)
            self.sitemap_text.insert(tk.END, "Invalid directory path")

    def get_sitemap(self, directory):
        sitemap_lines = []
        total_items = sum([len(files) + len(dirs) for _, dirs, files in os.walk(directory)])
        processed_items = 0

        for root, dirs, files in os.walk(directory):
            level = root.replace(directory, '').count(os.sep)
            if level >= self.depth_var.get():
                dirs[:] = []
                continue
            
            if any(root.startswith(excluded) for excluded in self.excluded_paths):
                dirs[:] = []
                continue

            folder_name = os.path.basename(root)
            folder_info = self.get_item_

    def get_item_info(self, path, is_dir=False):
        info = []
        if self.show_size_var.get() and not is_dir:
            size = os.path.getsize(path)
            info.append(f"({self.format_size(size)})")
        if self.show_date_var.get():
            mtime = os.path.getmtime(path)
            date_str = datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
            info.append(f"[{date_str}]")
        return " ".join(info)

    def format_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0

    def get_sitemap(self, directory):
        sitemap_lines = []
        total_items = sum([len(files) + len(dirs) for _, dirs, files in os.walk(directory)])
        processed_items = 0

        for root, dirs, files in os.walk(directory):
            level = root.replace(directory, '').count(os.sep)
            if level >= self.depth_var.get():
                dirs[:] = []
                continue
            
            if any(root.startswith(excluded) for excluded in self.excluded_paths):
                dirs[:] = []
                continue

            folder_name = os.path.basename(root)
            folder_info = self.get_item_info(root, is_dir=True)
            sitemap_lines.append(f"{'  ' * level}{folder_name}/{folder_info}")
            self.sitemap_data.append({"path": root, "type": "folder", "info": folder_info})

            for file in sorted(files):
                _, ext = os.path.splitext(file)
                if (self.included_types and ext.lower() not in self.included_types) or \
                   (self.excluded_types and ext.lower() in self.excluded_types):
                    continue

                file_path = os.path.join(root, file)
                file_info = self.get_item_info(file_path)
                sitemap_lines.append(f"{'  ' * (level + 1)}{file}{file_info}")
                self.sitemap_data.append({"path": file_path, "type": "file", "info": file_info})

                # Check for duplicate files
                file_hash = self.get_file_hash(file_path)
                if file_hash in self.duplicate_files:
                    self.duplicate_files[file_hash].append(file_path)
                else:
                    self.duplicate_files[file_hash] = [file_path]

            processed_items += len(dirs) + len(files)
            self.progress_var.set((processed_items / total_items) * 100)
            self.update_idletasks()

        self.progress_var.set(100)
        return "\n".join(sitemap_lines)

    def get_file_hash(self, file_path):
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            buf = f.read(65536)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(65536)
        return hasher.hexdigest()

    def populate_tree(self):
        for item in self.sitemap_data:
            parent = self.tree.insert('', 'end', text=os.path.basename(item['path']), values=(item['info'],))
            if item['type'] == 'folder':
                self.tree.item(parent, open=True)

    def show_duplicate_files(self):
        duplicates = [files for files in self.duplicate_files.values() if len(files) > 1]
        if duplicates:
            message = "Duplicate files found:\n\n"
            for group in duplicates:
                message += f"Group:\n" + "\n".join(f"  {file}" for file in group) + "\n\n"
            messagebox.showinfo("Duplicate Files", message)

    def save_sitemap(self, format):
        content = self.sitemap_text.get(1.0, tk.END)
        if not content.strip():
            messagebox.showwarning("Empty Sitemap", "Please generate a sitemap first.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=f".{format}",
                                                 filetypes=[(f"{format.upper()} files", f"*.{format}"), ("All files", "*.*")])
        if not file_path:
            return

        if format == "txt":
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
        elif format == "xml":
            root = ET.Element("sitemap")
            for item in self.sitemap_data:
                elem = ET.SubElement(root, "item")
                ET.SubElement(elem, "path").text = item['path']
                ET.SubElement(elem, "type").text = item['type']
                ET.SubElement(elem, "info").text = item['info']
            tree = ET.ElementTree(root)
            tree.write(file_path, encoding='utf-8', xml_declaration=True)
        elif format == "json":
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(self.sitemap_data, f, indent=2)
        elif format == "csv":
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["path", "type", "info"])
                writer.writeheader()
                writer.writerows(self.sitemap_data)

        messagebox.showinfo("Saved", f"Sitemap saved as {format.upper()} file.")

    def copy_sitemap(self):
        sitemap = self.sitemap_text.get(1.0, tk.END)
        self.clipboard_clear()
        self.clipboard_append(sitemap)
        messagebox.showinfo("Copied", "Sitemap copied to clipboard")

    def search_sitemap(self):
        query = self.search_var.get().lower()
        content = self.sitemap_text.get(1.0, tk.END)
        lines = content.split('\n')
        matched_lines = [line for line in lines if query in line.lower()]
        self.sitemap_text.delete(1.0, tk.END)
        self.sitemap_text.insert(tk.END, "\n".join(matched_lines))

if __name__ == "__main__":
    app = AdvancedSitemapGenerator()
    app.mainloop()