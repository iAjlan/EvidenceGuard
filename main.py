import os
import shutil
import time
import threading
import hashlib
import tkinter as tk
from tkinter import filedialog, scrolledtext
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

TARGET_DIR = ""
BACKUP_DIR = ""
is_monitoring = False
observer = None
HASH_DATABASE = {}
RESTORED_COUNT = 0
TAMPER_COUNT = 0
LAST_EVENT = {}
RESTORING = set()

def calculate_sha256(filepath):
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except:
        return None


def update_counters():
    counter_label.config(
        text=f"Detected Modifications: {TAMPER_COUNT} | Restored Files: {RESTORED_COUNT}"
    )

def log_to_gui(message):
    def update():
        log_area.config(state=tk.NORMAL)
        log_area.insert(tk.END, message + "\n")
        log_area.see(tk.END)
        log_area.config(state=tk.DISABLED)
    root.after(0, update)

class AggressiveWatchdog(FileSystemEventHandler):

    def on_deleted(self, event):
        if not event.is_directory:
            filename = os.path.basename(event.src_path)
            backup_path = os.path.join(BACKUP_DIR, filename)
            if os.path.exists(backup_path):
                shutil.copy2(backup_path, event.src_path)
                global RESTORED_COUNT
                RESTORED_COUNT += 1
                root.after(0, update_counters)
                log_to_gui(f"[+] Restored deleted file: {filename}")


    def on_moved(self, event):
        if event.is_directory:
            return
        filename = os.path.basename(event.src_path)
        backup_path = os.path.join(BACKUP_DIR, filename)
        if os.path.exists(backup_path) and os.path.exists(event.dest_path):
            shutil.move(event.dest_path, event.src_path)
            log_to_gui(f"[+] Moved back: {filename}")

    def on_created(self, event):
        if not event.is_directory:
            filename = os.path.basename(event.src_path)
            if filename.startswith("~$"):
                return
            backup_path = os.path.join(BACKUP_DIR, filename)
            if os.path.exists(backup_path):
                return
            log_to_gui(f"[!] Blocked creation: {filename}")
            time.sleep(0.5)
            try:
                os.remove(event.src_path)
            except:
                pass

    def on_modified(self, event):
        if event.is_directory:
            return

        filename = os.path.basename(event.src_path)
        if filename in RESTORING:
            return
        now=time.time()
        if now-LAST_EVENT.get(filename,0)<1:
            return
        LAST_EVENT[filename]=now
        if filename.startswith("~$"):
            return

        backup_path = os.path.join(BACKUP_DIR, filename)

        if os.path.exists(backup_path) and os.path.exists(event.src_path):
            current_hash=None
            for _i in range(10):
                current_hash=calculate_sha256(event.src_path)
                if current_hash:
                    break
                time.sleep(0.1)
            original_hash = HASH_DATABASE.get(filename)

            if current_hash != original_hash:
                global TAMPER_COUNT
                TAMPER_COUNT += 1
                root.after(0, update_counters)
                log_to_gui(f"[!] Evidence tampering detected: {filename}")
                log_to_gui(f"Original SHA256: {original_hash}")
                log_to_gui(f"Modified SHA256: {current_hash}")

                def force_restore():
                    for _ in range(20):
                        try:
                            shutil.copy2(backup_path, event.src_path)
                            restored_hash = calculate_sha256(event.src_path)
                            global RESTORED_COUNT
                            RESTORED_COUNT += 1
                            root.after(0, update_counters)
                            log_to_gui("🟢 File restored successfully.")
                            log_to_gui(f"Original SHA256 : {original_hash}")
                            log_to_gui(f"Modified SHA256 : {current_hash}")
                            log_to_gui(f"Current SHA256  : {restored_hash}")
                            log_to_gui("✔ Restored to original hash." if restored_hash==original_hash else "✗ Restore failed.")
                            RESTORING.discard(filename)
                            break
                        except:
                            time.sleep(0.5)

                threading.Thread(target=force_restore, daemon=True).start()

def emergency_kill_switch(event=None):
    global observer

    try:
        if observer:
            observer.stop()
            observer.join()
    except:
        pass

    root.destroy()

def start_monitoring():
    global is_monitoring, observer, TARGET_DIR, BACKUP_DIR, HASH_DATABASE

    TARGET_DIR = filedialog.askdirectory(title="Select Evidence Folder")
    if not TARGET_DIR:
        return

    BACKUP_DIR = os.path.join(os.environ['TEMP'], "DFIR_Backup")

    if os.path.exists(BACKUP_DIR):
        shutil.rmtree(BACKUP_DIR)

    shutil.copytree(TARGET_DIR, BACKUP_DIR)

    HASH_DATABASE = {}
    global RESTORED_COUNT, TAMPER_COUNT
    RESTORED_COUNT = 0
    TAMPER_COUNT = 0
    update_counters()

    for root_dir, dirs, files in os.walk(TARGET_DIR):
        for file in files:
            full_path = os.path.join(root_dir, file)
            file_hash = calculate_sha256(full_path)
            if file_hash:
                HASH_DATABASE[file] = file_hash
                log_to_gui(f"[HASH] {file}: {file_hash[:20]}...")

    event_handler = AggressiveWatchdog()
    observer = Observer()
    observer.schedule(event_handler, TARGET_DIR, recursive=True)
    observer.start()

    is_monitoring = True
    lbl_status.config(text="Status: ACTIVE 🟢", fg="lime")
    log_to_gui("=== Monitoring Started ===")

def stop_monitoring():
    global is_monitoring, observer
    if observer and is_monitoring:
        observer.stop()
        observer.join()
        is_monitoring = False
        lbl_status.config(text="Status: STOPPED 🔴", fg="red")
        log_to_gui("=== Monitoring Stopped ===")

root = tk.Tk()
root.title("EvidenceGuard")
root.geometry("650x700")
root.configure(bg="#121212")
root.bind('<F12>', emergency_kill_switch)

try:
    root.iconphoto(False, tk.PhotoImage(file="icon.png"))
except:
    pass

lbl_title = tk.Label(root, text="Evidence Protection Tool",
                     font=("Arial", 16, "bold"),
                     bg="black", fg="#00BFFF")
lbl_title.pack(pady=10)

try:
    img = tk.PhotoImage(file="logo.png")
    img = img.subsample(5, 5)
    lbl_img = tk.Label(root, image=img, bg="black")
    lbl_img.image = img
    lbl_img.pack(pady=10)
    lbl_dev = tk.Label(
        root,
        text="Created by: Ajlan Al Shammari",
        font=("Arial",11,"bold"),
        bg="#121212",
        fg="#FFD700"
    )
    lbl_dev.pack(pady=(0,15))
except:
    pass

log_area = scrolledtext.ScrolledText(
    root, width=60, height=14,
    bg="#1A1A1A", fg="white",
    font=("Consolas", 10)
)
log_area.pack(pady=10, padx=10)
log_area.config(state=tk.DISABLED)


counter_label = tk.Label(
    root,
    text="Detected Modifications: 0 | Restored Files: 0",
    font=("Arial", 10, "bold"),
    bg="black",
    fg="#FFD700"
)
counter_label.pack(pady=5)

lbl_status = tk.Label(
    root,
    text="Status: STOPPED 🔴",
    font=("Arial", 12, "bold"),
    bg="black",
    fg="red"
)
lbl_status.pack(pady=5)

btn_start = tk.Button(
    root,
    text="🔒 START PROTECTION",
    font=("Arial", 12, "bold"),
    bg="green",
    fg="white",
    command=start_monitoring
)
btn_start.pack(pady=5, fill='x', padx=50)

btn_stop = tk.Button(
    root,
    text="🔓 STOP PROTECTION",
    font=("Arial", 12, "bold"),
    bg="red",
    fg="white",
    command=stop_monitoring
)
btn_stop.pack(pady=5, fill='x', padx=50)


lbl_kill = tk.Label(
    root,
    text="Emergency Kill Switch: Press F12",
    font=("Arial", 10, "bold"),
    bg="black",
    fg="orange"
)
lbl_kill.pack(side="bottom", pady=5)


root.mainloop()
