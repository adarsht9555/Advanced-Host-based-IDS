import os
import json
import shutil
import hashlib
import time
import threading
import tkinter as tk
from tkinter import messagebox, filedialog, ttk
from tkinter.scrolledtext import ScrolledText
from datetime import datetime

class HIDS_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Host-based IDS")
        self.directory = None
        self.file_hashes = {}
        self.monitoring = False
        self.monitor_thread = None
        # new features: baseline store and logging
        self.BASELINE_FILE = os.path.join(os.path.expanduser('~'), '.simple_hids_baseline.json')
        self.LOG_FILE = os.path.join(os.path.expanduser('~'), '.simple_hids_log.txt')
        self.QUARANTINE_DIR = os.path.join(os.path.expanduser('~'), '.simple_hids_quarantine')
        self.QUAR_IDX_FILE = os.path.join(self.QUARANTINE_DIR, 'quarantine_index.json')
        self.quarantine_index = self.load_quarantine_index()
        self.auto_quarantine = False
        self.baseline_store = self.load_baseline_store()
        # adjustable scan interval (seconds)
        self.scan_interval = 10

        self.create_widgets()
        self.configure_styles()

    def create_widgets(self):
        # Frame for controls
        control_frame = tk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        self.dir_label = tk.Label(control_frame, text="Not monitoring any directory.")
        self.dir_label.pack(side=tk.LEFT, padx=(0, 10))

        self.browse_button = tk.Button(control_frame, text="Browse", command=self.browse_directory)
        self.browse_button.pack(side=tk.LEFT, padx=5)

        self.start_button = tk.Button(control_frame, text="Start", command=self.start_monitoring, state=tk.DISABLED)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = tk.Button(control_frame, text="Stop", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Scan interval control
        tk.Label(control_frame, text='Scan interval (s):').pack(side=tk.LEFT, padx=(8,2))
        self.interval_var = tk.IntVar(value=self.scan_interval)
        self.interval_spin = tk.Spinbox(control_frame, from_=1, to=3600, width=5, textvariable=self.interval_var, command=self.update_interval)
        self.interval_spin.pack(side=tk.LEFT, padx=2)

        # Show log button
        self.log_button = tk.Button(control_frame, text="Show Log", command=self.show_log)
        self.log_button.pack(side=tk.RIGHT, padx=5)

        # Auto-quarantine checkbox and manage button
        self.auto_quar_var = tk.BooleanVar(value=self.auto_quarantine)
        self.auto_quar_cb = tk.Checkbutton(control_frame, text='Auto-Quarantine (move suspicious files)', variable=self.auto_quar_var, command=self.toggle_auto_quarantine)
        self.auto_quar_cb.pack(side=tk.RIGHT, padx=5)
        self.manage_quar_button = tk.Button(control_frame, text='Manage Quarantine', command=self.manage_quarantine)
        self.manage_quar_button.pack(side=tk.RIGHT, padx=5)
        # Treeview for file status
        self.tree = ttk.Treeview(self.root, columns=("File", "Status", "Last Modified", "Hash"), show="headings")
        self.tree.heading("File", text="File")
        self.tree.heading("Status", text="Status")
        self.tree.heading("Last Modified", text="Last Modified")
        self.tree.heading("Hash", text="Hash (SHA-256)")

        self.tree.column("File", width=300)
        self.tree.column("Status", width=100, anchor=tk.CENTER)
        self.tree.column("Last Modified", width=150, anchor=tk.CENTER)
        self.tree.column("Hash", width=400)

        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Status bar
        self.status_bar = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def configure_styles(self):
        self.tree.tag_configure("OK", foreground="green")
        self.tree.tag_configure("Modified", foreground="orange")
        self.tree.tag_configure("New", foreground="blue")
        self.tree.tag_configure("Deleted", foreground="red")
        self.tree.tag_configure("Quarantined", foreground="purple")

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.directory = directory
            self.dir_label.config(text=f"Monitoring: {self.directory}")
            self.start_button.config(state=tk.NORMAL)
            self.initial_scan()

    def hash_file(self, filepath):
        # Chunked/read-in-stream hashing to avoid memory spikes on large files
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None

    def get_file_mtime(self, filepath):
        try:
            mtime = os.path.getmtime(filepath)
            return datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            return "N/A"

    def initial_scan(self):
        # Build current snapshot
        current = {}
        for rootp, dirs, files in os.walk(self.directory):
            for file in files:
                filepath = os.path.join(rootp, file)
                file_hash = self.hash_file(filepath)
                if file_hash:
                    current[filepath] = (file_hash, self.get_file_mtime(filepath))

        # If we have a saved baseline for this directory, compare and show diffs
        saved = self.baseline_store.get(self.directory)
        if saved:
            file_status = {}
            # detect new and modified
            for path, (h, m) in current.items():
                if path not in saved:
                    file_status[path] = 'New'
                elif saved[path][0] != h:
                    file_status[path] = 'Modified'
            # detect deleted
            for path in saved:
                if path not in current:
                    file_status[path] = 'Deleted'

            self.file_hashes = current
            self.update_treeview(file_status)
            self.status_bar.config(text=f"Initial scan complete. Compared to saved baseline; changes: {len(file_status)}")
        else:
            self.file_hashes = current
            self.update_treeview(initial=True)
            self.status_bar.config(text=f"Initial scan complete. {len(self.file_hashes)} files monitored.")

        # Persist baseline for this directory
        self.baseline_store[self.directory] = self.file_hashes.copy()
        self.save_baseline_store()

        # ensure quarantine dir exists
        self.ensure_quarantine_dir()
    def update_treeview(self, file_status=None, initial=False):
        self.tree.delete(*self.tree.get_children())
        
        all_files = set(self.file_hashes.keys())
        if file_status:
            all_files.update(file_status.keys())

        for filepath in sorted(list(all_files)):
            if initial:
                file_hash, mtime = self.file_hashes[filepath]
                status = "OK"
                self.tree.insert('', 'end', values=(filepath, status, mtime, file_hash), tags=(status,))
            elif file_status:
                status = file_status.get(filepath, "OK")
                if status == "Deleted":
                    file_hash, mtime = self.file_hashes.get(filepath, ("N/A", "N/A"))
                    self.tree.insert('', 'end', values=(filepath, status, mtime, file_hash), tags=(status,))
                else:
                    try:
                        new_hash, new_mtime = self.hash_file(filepath), self.get_file_mtime(filepath)
                        if new_hash:
                             self.tree.insert('', 'end', values=(filepath, status, new_mtime, new_hash), tags=(status,))
                    except FileNotFoundError:
                        # This can happen if a file is deleted during the scan
                        continue

    # --- baseline store and logging helpers ---
    def load_baseline_store(self):
        try:
            if os.path.exists(self.BASELINE_FILE):
                with open(self.BASELINE_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            return {}
        return {}

    def save_baseline_store(self):
        try:
            with open(self.BASELINE_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.baseline_store, f, indent=2)
        except Exception:
            pass

    def update_interval(self):
        try:
            v = int(self.interval_var.get())
            if v >= 1:
                self.scan_interval = v
                self.status_bar.config(text=f"Scan interval set to {self.scan_interval}s")
        except Exception:
            pass

    def log_change(self, file_status):
        try:
            ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(self.LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(f"[{ts}] Changes in {self.directory}\n")
                for path, status in file_status.items():
                    f.write(f"    {status}: {path}\n")
                f.write('\n')
        except Exception:
            pass

    def show_log(self):
        win = tk.Toplevel(self.root)
        win.title('HIDS Log')
        txt = ScrolledText(win, width=100, height=30)
        txt.pack(fill=tk.BOTH, expand=True)
        try:
            if os.path.exists(self.LOG_FILE):
                with open(self.LOG_FILE, 'r', encoding='utf-8') as f:
                    txt.insert('1.0', f.read())
            else:
                txt.insert('1.0', 'Log is empty.')
        except Exception as e:
            txt.insert('1.0', f'Error reading log: {e}')
        txt.config(state='disabled')
        ttk.Button(win, text='Close', command=win.destroy).pack(pady=4)

    # --- Quarantine helpers ---
    def ensure_quarantine_dir(self):
        try:
            os.makedirs(self.QUARANTINE_DIR, exist_ok=True)
        except Exception:
            pass

    def load_quarantine_index(self):
        try:
            if os.path.exists(self.QUAR_IDX_FILE):
                with open(self.QUAR_IDX_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            return {}
        return {}

    def save_quarantine_index(self):
        try:
            self.ensure_quarantine_dir()
            with open(self.QUAR_IDX_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.quarantine_index, f, indent=2)
        except Exception:
            pass

    def toggle_auto_quarantine(self):
        self.auto_quarantine = bool(self.auto_quar_var.get())
        self.status_bar.config(text=f"Auto-Quarantine {'enabled' if self.auto_quarantine else 'disabled'}")

    def quarantine_file(self, filepath, status_label):
        # Move file to quarantine dir and record original path
        try:
            if not os.path.exists(filepath):
                return False, 'missing'
            self.ensure_quarantine_dir()
            base = os.path.basename(filepath)
            ts = datetime.now().strftime('%Y%m%dT%H%M%S')
            qname = f"{ts}_{base}"
            qpath = os.path.join(self.QUARANTINE_DIR, qname)
            # Prefer move to preserve file; fallback to copy
            try:
                shutil.move(filepath, qpath)
            except Exception:
                try:
                    shutil.copy2(filepath, qpath)
                    os.remove(filepath)
                except Exception as e:
                    self.log_change({filepath: f'Quarantine failed: {e}'})
                    return False, 'failed'

            # record metadata
            try:
                orig_mtime = self.get_file_mtime(qpath)
            except Exception:
                orig_mtime = 'N/A'
            self.quarantine_index[qname] = {'original_path': filepath, 'quarantined_at': datetime.now().isoformat(), 'original_mtime': orig_mtime, 'status': status_label}
            self.save_quarantine_index()
            self.log_change({filepath: f'Quarantined as {qname}'})
            return True, qname
        except Exception as e:
            self.log_change({filepath: f'Quarantine error: {e}'})
            return False, 'error'

    def manage_quarantine(self):
        win = tk.Toplevel(self.root)
        win.title('Quarantine Manager')
        win.geometry('800x400')
        listbox = tk.Listbox(win, width=120)
        listbox.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        items = []
        for qname, meta in sorted(self.quarantine_index.items(), key=lambda x: x[1].get('quarantined_at','')):
            line = f"{qname}  --  original: {meta.get('original_path')}  --  quarantined_at: {meta.get('quarantined_at')}"
            items.append((qname, line))
            listbox.insert(tk.END, line)

        def do_restore():
            sel = listbox.curselection()
            if not sel:
                return
            idx = sel[0]
            qname = items[idx][0]
            meta = self.quarantine_index.get(qname)
            if not meta:
                return
            qpath = os.path.join(self.QUARANTINE_DIR, qname)
            orig = meta.get('original_path')
            # ensure parent dir
            try:
                parent = os.path.dirname(orig)
                os.makedirs(parent, exist_ok=True)
                # if original exists, append suffix
                dest = orig
                if os.path.exists(dest):
                    dest = orig + f".restored_{datetime.now().strftime('%Y%m%dT%H%M%S')}"
                shutil.move(qpath, dest)
                self.log_change({orig: f'Restored from {qname} to {dest}'})
                del self.quarantine_index[qname]
                self.save_quarantine_index()
                listbox.delete(idx)
            except Exception as e:
                messagebox.showerror('Restore failed', str(e))

        def do_delete():
            sel = listbox.curselection()
            if not sel:
                return
            idx = sel[0]
            qname = items[idx][0]
            qpath = os.path.join(self.QUARANTINE_DIR, qname)
            try:
                if os.path.exists(qpath):
                    os.remove(qpath)
                self.log_change({qname: 'Deleted from quarantine'})
                if qname in self.quarantine_index:
                    del self.quarantine_index[qname]
                    self.save_quarantine_index()
                listbox.delete(idx)
            except Exception as e:
                messagebox.showerror('Delete failed', str(e))

        btn_frame = tk.Frame(win)
        btn_frame.pack(fill=tk.X)
        tk.Button(btn_frame, text='Restore Selected', command=do_restore).pack(side=tk.LEFT, padx=6, pady=6)
        tk.Button(btn_frame, text='Delete Selected', command=do_delete).pack(side=tk.LEFT, padx=6, pady=6)
        tk.Button(btn_frame, text='Open Quarantine Folder', command=lambda: os.startfile(self.QUARANTINE_DIR) if os.path.exists(self.QUARANTINE_DIR) else None).pack(side=tk.RIGHT, padx=6, pady=6)


    def monitor_files(self):
        while self.monitoring:
            self.status_bar.config(text=f"Scanning for changes... Last scan: {datetime.now().strftime('%H:%M:%S')}")
            file_status = {}
            changed_files = False
            current_hashes = {}
            
            # Check for new and modified files
            for root, dirs, files in os.walk(self.directory):
                for file in files:
                    filepath = os.path.join(root, file)
                    file_hash = self.hash_file(filepath)
                    if not file_hash:
                        continue
                    
                    current_hashes[filepath] = (file_hash, self.get_file_mtime(filepath))

                    if filepath not in self.file_hashes:
                        file_status[filepath] = "New"
                        changed_files = True
                    elif self.file_hashes[filepath][0] != file_hash:
                        file_status[filepath] = "Modified"
                        changed_files = True

            # Check for deleted files
            for old_file in self.file_hashes:
                if old_file not in current_hashes:
                    file_status[old_file] = "Deleted"
                    changed_files = True

            if changed_files:
                # Auto-quarantine new or modified files if enabled
                if self.auto_quarantine:
                    to_quarantine = []
                    for path, status in list(file_status.items()):
                        if status in ('New', 'Modified'):
                            to_quarantine.append((path, status))
                    for path, st in to_quarantine:
                        ok, qname = self.quarantine_file(path, st)
                        if ok:
                            # reflect change in UI/logs
                            file_status[path] = 'Quarantined'
                        else:
                            file_status[path] = f'QuarantineFailed({qname})'

                self.update_treeview(file_status)
                # alert user (modal) and also write to log
                try:
                    self.alert_user(file_status)
                except Exception:
                    pass
                self.log_change(file_status)
                # Update baseline
                new_baseline = {}
                for path, (h,m) in current_hashes.items():
                    new_baseline[path] = (h, m)
                for path, status in file_status.items():
                    if status == "Deleted":
                       pass # Don't add deleted files to new baseline
                    elif path not in new_baseline: # for new files
                        new_baseline[path] = (self.hash_file(path), self.get_file_mtime(path))
                self.file_hashes = new_baseline
                # persist baseline store
                self.baseline_store[self.directory] = self.file_hashes.copy()
                self.save_baseline_store()
                
            self.status_bar.config(text=f"Scan complete. Last scan: {datetime.now().strftime('%H:%M:%S')}")
            # use configurable interval
            time.sleep(self.scan_interval)

    def alert_user(self, file_status):
        message = "File system changes detected:\n\n"
        for file, status in file_status.items():
            message += f"- {file}: {status}\n"
        messagebox.showwarning("HIDS Alert", message)

    def start_monitoring(self):
        if not self.directory:
            messagebox.showerror("Error", "Please select a directory to monitor first.")
            return
        
        self.monitoring = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.browse_button.config(state=tk.DISABLED)
        self.status_bar.config(text="Monitoring started...")

        self.monitor_thread = threading.Thread(target=self.monitor_files, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.browse_button.config(state=tk.NORMAL)
        self.status_bar.config(text="Monitoring stopped.")
        if self.monitor_thread and self.monitor_thread.is_alive():
            # The thread will exit on its own since self.monitoring is False
            pass

if __name__ == "__main__":
    root = tk.Tk()
    app = HIDS_GUI(root)
    root.geometry('1000x600')
    root.mainloop()
