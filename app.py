import requests
import os
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from dotenv import load_dotenv
from datetime import datetime
import tkinter.font as tkfont
import threading

load_dotenv()
token = os.getenv("TOKEN")

if not token:
    messagebox.showerror("Error", "Token not defined in .env file")
    exit()

headers = {
    "Authorization": f"Bearer {token}",
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json, text/plain, */*",
}

# Endpoints
list_machines_url = "https://labs.hackthebox.com/api/v4/season/machines"
activate_machine_url = "https://labs.hackthebox.com/api/v4/vm/spawn"
status_machine_url = "https://labs.hackthebox.com/api/v4/machine/active"
stop_machine_url = "https://labs.hackthebox.com/api/v4/vm/terminate"
submit_flag_url = "https://labs.hackthebox.com/api/v4/machine/own"
reset_machine_url = "https://labs.hackthebox.com/api/v4/vm/reset"
activity_url = "https://labs.hackthebox.com/api/v4/machine/owns/top"

session = requests.Session()
#session.proxies = {"https": "http://127.0.0.1:8080"}
#session.verify = False

def list_machines():
    response = session.get(list_machines_url, headers=headers, timeout=20)
    return response.json().get("data", []) if response.status_code == 200 else []

def activate_machine(machine_id):
    payload = {"machine_id": machine_id}
    response = session.post(activate_machine_url, headers=headers, json=payload, timeout=20)
    if response.status_code == 200:
        return True, response.json().get("message", "Machine spawned successfully")
    try:
        error_data = response.json()
        return False, error_data.get("message", "Unknown error")
    except:
        return False, f"Error {response.status_code}: {response.text}"

def stop_machine():
    response = session.post(stop_machine_url, headers=headers, timeout=20)
    return response.status_code == 200

def get_machine_status():
    response = session.get(status_machine_url, headers=headers, timeout=20)
    return response.json().get("info", {}) if response.status_code == 200 else None

def submit_flag(machine_id, flag):
    payload = {"machine_id": machine_id, "flag": flag}
    response = session.post(submit_flag_url, headers=headers, json=payload, timeout=20)
    return response.status_code == 200

def reset_machine(machine_id):
    payload = {"machine_id": machine_id}
    response = session.post(reset_machine_url, headers=headers, json=payload, timeout=20)
    if response.status_code == 200:
        return True, response.json().get("message", "Machine reset successfully")
    try:
        error_data = response.json()
        return False, error_data.get("message", "Unknown error")
    except:
        return False, f"Error {response.status_code}: {response.text}"

class HTBGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("HTB Commander")
        self.root.geometry("800x600")
        self.machine_dict = {}
        self.reset_btn = None
        self.copy_ip_btn = None
        
        self.setup_style()
        self.setup_layout()
        self.load_machines()
        self.setup_activity()
        self.bind_events()
        
        # Iniciar la actualización periódica de la actividad
        self.update_activity()

    def setup_style(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        bg_color = '#1a1a1a'
        accent_color = '#2a7f3f'
        text_color = '#c0c0c0'
        panel_bg = '#2a2a2a'
        
        self.style.configure('.', background=bg_color, foreground=text_color)
        self.style.configure('TButton', 
                             background=panel_bg, 
                             foreground=text_color,
                             borderwidth=1,
                             relief='flat',
                             font=('Iosevka Nerd Font', 10))
        self.style.map('TButton',
                       background=[('active', accent_color), ('disabled', bg_color)],
                       foreground=[('active', '#ffffff')])
        self.style.configure('TLabel', background=bg_color, foreground=text_color)
        self.style.configure('TLabelframe', background=bg_color, relief='flat')
        self.style.configure('TLabelframe.Label', background=bg_color, foreground=accent_color)
        self.style.configure('TCombobox', fieldbackground=panel_bg, foreground=text_color)
        self.style.configure('TEntry', fieldbackground=panel_bg, insertcolor=text_color)
        self.root.configure(bg=bg_color)

    def setup_layout(self):
        # Panel principal
        main_panel = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_panel.pack(fill=tk.BOTH, expand=True)
        
        # Panel izquierdo
        left_panel = ttk.Frame(main_panel, width=200)
        main_panel.add(left_panel, weight=0)
        self.setup_left_panel(left_panel)
        
        # Panel derecho
        right_panel = ttk.Frame(main_panel)
        main_panel.add(right_panel, weight=1)
        self.setup_right_panel(right_panel)
        
        # Consola y Activity
        self.setup_console()

    def setup_left_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Machines")
        frame.pack(padx=10, pady=10, fill=tk.X)
        
        self.machine_list = ttk.Combobox(frame, state="readonly", font=('Iosevka Nerd Font', 9))
        self.machine_list.pack(pady=5, fill=tk.X, padx=5)
        
        ttk.Button(frame, 
                   text="⟳ Refresh List", 
                   command=self.load_machines).pack(pady=5, fill=tk.X)
        ttk.Button(frame, 
                   text="▶ Spawn Machine", 
                   command=self.spawn_machine).pack(pady=5, fill=tk.X)
        ttk.Button(frame, 
                   text="⏹ Stop Machine", 
                   command=self.stop_machine).pack(pady=5, fill=tk.X)
        self.reset_btn = ttk.Button(frame, 
                                     text="🔄 Reset Machine", 
                                     command=self.reset_machine)
        self.reset_btn.pack(pady=5, fill=tk.X)

    def setup_right_panel(self, parent):
        status_frame = ttk.LabelFrame(parent, text="Machine Info")
        status_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Header
        header = ttk.Frame(status_frame)
        header.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(header, text="Current Status", font=('Iosevka Nerd Font', 9, 'bold')).pack(side=tk.LEFT)
        ttk.Button(header, text="⟳ Refresh", command=self.check_status, width=10).pack(side=tk.RIGHT)
        
        # Grid de estado
        grid_frame = ttk.Frame(status_frame)
        grid_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        fields = [
            ("Machine Name:", "name"),
            ("IP Address:", "ip"),
            ("Type:", "type"),
            ("Lab Server:", "lab_server"),
            ("Expiration:", "expires_at")
        ]
        self.status_labels = {}
        for row, (label, key) in enumerate(fields):
            ttk.Label(grid_frame, text=label, font=('Iosevka Nerd Font', 9, 'bold')).grid(row=row, column=0, sticky=tk.W, padx=5, pady=2)
            self.status_labels[key] = ttk.Label(grid_frame, text="N/A", font=('Iosevka Nerd Font', 9), foreground='#3fbf7f')
            self.status_labels[key].grid(row=row, column=1, sticky=tk.W, pady=2)
            if key == "ip":
                self.copy_ip_btn = ttk.Button(grid_frame,
                                              text="📋",
                                              command=self.copy_ip,
                                              width=3,
                                              state='disabled')
                self.copy_ip_btn.grid(row=row, column=2, padx=5)

        # Sección de flag
        flag_frame = ttk.LabelFrame(parent, text="Submit Flag")
        flag_frame.pack(padx=10, pady=10, fill=tk.X)
        self.flag_entry = ttk.Entry(flag_frame, font=('Iosevka Nerd Font', 10))
        self.flag_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        ttk.Button(flag_frame, text="🚩 Submit", command=self.submit_flag).pack(side=tk.RIGHT, padx=5)

    def setup_console(self):
        console_panel = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        console_panel.pack(padx=10, pady=5, fill=tk.BOTH, expand=True, side=tk.BOTTOM)
        
        # Sección Activity
        activity_frame = ttk.LabelFrame(console_panel, text="Activity")
        console_panel.add(activity_frame, weight=1)
        columns = ('position', 'name', 'rank', 'user_time', 'root_time', 'blood')
        self.activity_tree = ttk.Treeview(activity_frame,
                                          columns=columns,
                                          show='headings',
                                          style='Custom.Treeview',
                                          height=30)
        # Configuración de encabezados
        self.activity_tree.heading('position', text='Pos')
        self.activity_tree.heading('name', text='Name')
        self.activity_tree.heading('rank', text='Rank')
        self.activity_tree.heading('user_time', text='User Time')
        self.activity_tree.heading('root_time', text='Root Time')
        self.activity_tree.heading('blood', text='Blood')
        scrollbar = ttk.Scrollbar(activity_frame, orient=tk.VERTICAL, command=self.activity_tree.yview)
        self.activity_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.activity_tree.pack(fill=tk.BOTH, expand=True)
        
        # Sección Console
        console_frame = ttk.LabelFrame(console_panel, text="Console")
        console_panel.add(console_frame, weight=1)
        self.console = scrolledtext.ScrolledText(console_frame,
                                                  bg='#2a2a2a',
                                                  fg='#c0c0c0',
                                                  insertbackground='white',
                                                  font=('Consolas', 8),
                                                  state='disabled')
        self.console.pack(fill=tk.BOTH, expand=True)

    def setup_activity(self):
        # Fuente para el Treeview
        self.activity_font = ('Iosevka Nerd Font', 8)
        self.header_font = ('Iosevka Nerd Font', 8, 'bold')
        # Configuración de estilo del Treeview
        self.style.configure('Custom.Treeview', 
                             background='#2a2a2a',
                             foreground='#c0c0c0',
                             fieldbackground='#2a2a2a',
                             font=self.activity_font,
                             rowheight=40)
        self.style.configure('Custom.Treeview.Heading', 
                             background='#1a1a1a',
                             foreground='#2a7f3f',
                             font=self.header_font,
                             relief='flat')
        self.style.map('Custom.Treeview', background=[('selected', '#2a7f3f')])
        # Configurar columnas
        self.activity_tree.column('position', width=40, anchor=tk.CENTER, stretch=False)
        self.activity_tree.column('name', width=160, anchor=tk.W)
        self.activity_tree.column('rank', width=90, anchor=tk.W)
        self.activity_tree.column('user_time', width=100, anchor=tk.CENTER)
        self.activity_tree.column('root_time', width=100, anchor=tk.CENTER)
        self.activity_tree.column('blood', width=60, anchor=tk.CENTER)
        for col in self.activity_tree['columns']:
            self.activity_tree.heading(col, anchor=tk.CENTER)

    def bind_events(self):
        # Al cambiar la selección se actualiza activity y status
        self.machine_list.bind("<<ComboboxSelected>>", self.on_machine_selected)

    def on_machine_selected(self, event):
        selected = self.machine_list.get()
        self.log_to_console(f"Máquina seleccionada: {selected}")
        # Actualiza actividad y status inmediatamente
        self.update_activity()
        self.check_status()

    def update_activity(self):
        # Ejecutar la solicitud en un hilo separado
        threading.Thread(target=self.fetch_activity, daemon=True).start()
        # Programar la próxima actualización cada 15 segundos
        self.root.after(10000 + 15000, self.update_activity)

    def fetch_activity(self):
        selected = self.machine_list.get()
        if not selected:
            self.root.after(0, lambda: self.log_to_console("No hay máquina seleccionada para actualizar la actividad", "warning"))
            self.root.after(0, lambda: self.activity_tree.delete(*self.activity_tree.get_children()))
        else:
            machine_id = self.machine_dict.get(selected)
            try:
                response = session.get(f"{activity_url}/{machine_id}", headers=headers, timeout=20)
                if response.status_code == 200:
                    data = response.json().get("info", [])
                    # Actualizar la UI en el hilo principal
                    self.root.after(0, lambda: self.update_activity_tree(data))
                else:
                    self.root.after(0, lambda: self.log_to_console(f"Activity update failed: {response.status_code}", "error"))
            except Exception as e:
                self.root.after(0, lambda: self.log_to_console(f"Activity error: {str(e)}", "error"))
    def update_activity_tree(self, data):
        # Limpiar datos anteriores
        for item in self.activity_tree.get_children():
            self.activity_tree.delete(item)
        # Insertar nuevos datos
        for entry in data:
            blood_status = ""
            if entry.get('is_user_blood', False):
                blood_status += "🩸"
            if entry.get('is_root_blood', False):
                blood_status += "🩸"
            user_time = entry.get('user_own_time', '0H 00M 00S').replace('H', 'H ').replace('M', 'M ')
            root_time = entry.get('root_own_time', '0H 00M 00S').replace('H', 'H ').replace('M', 'M ')
            name = entry.get('name', 'Unknown')
            if len(name) > 15:
                name = f"{name[:12]}..."
            self.activity_tree.insert('', tk.END, values=(
                entry.get('position', '-'),
                name,
                entry.get('rank_text', '-'),
                user_time,
                root_time,
                blood_status
            ))
        # Ajuste dinámico del ancho de columnas
        for col in self.activity_tree['columns']:
            max_width = max(
                tkfont.Font(font=self.activity_font).measure(str(self.activity_tree.set(child, col)))
                for child in self.activity_tree.get_children()
            )
            self.activity_tree.column(col, width=max_width + 20, minwidth=50)

    def log_to_console(self, message, tag=None):
        self.console.configure(state='normal')
        self.console.insert(tk.END, f"> {message}\n", tag)
        self.console.configure(state='disabled')
        self.console.see(tk.END)

    def copy_ip(self):
        ip = self.status_labels["ip"].cget("text")
        if ip != "N/A":
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)
            self.log_to_console(f"Copied IP to clipboard: {ip}")

    def load_machines(self):
        try:
            machines = list_machines()
            self.machine_dict = {m.get("name"): m.get("id") for m in machines}
            self.machine_list["values"] = list(self.machine_dict.keys())
            if self.machine_list["values"]:
                self.machine_list.current(0)
            self.log_to_console(f"Loaded {len(machines)} machines")
        except Exception as e:
            self.log_to_console(f"Error loading machines: {str(e)}", "error")

    def spawn_machine(self):
        selected = self.machine_list.get()
        if not selected:
            messagebox.showerror("Error", "Select a machine first")
            return
        machine_id = self.machine_dict.get(selected)
        success, msg = activate_machine(machine_id)
        if success:
            self.log_to_console(f"Spawned machine: {selected}")
            self.check_status()
            messagebox.showinfo("Success", msg)
        else:
            self.log_to_console(f"Spawn failed: {msg}", "error")
            messagebox.showerror("Error", msg)

    def stop_machine(self):
        if stop_machine():
            self.log_to_console("Machine stopped")
            self.check_status()
            messagebox.showinfo("Success", "Machine stopped successfully")
        else:
            self.log_to_console("Failed to stop machine", "error")
            messagebox.showerror("Error", "Failed to stop machine")

    def reset_machine(self):
        selected = self.machine_list.get()
        if not selected:
            messagebox.showerror("Error", "Select a machine first")
            return
        machine_id = self.machine_dict.get(selected)
        success, msg = reset_machine(machine_id)
        if success:
            self.log_to_console(f"Reset machine: {selected}")
            self.check_status()
            messagebox.showinfo("Success", msg)
        else:
            self.log_to_console(f"Reset failed: {msg}", "error")
            messagebox.showerror("Error", msg)

    def check_status(self):
        try:
            status = get_machine_status()
            if status:
                self.status_labels["name"].config(text=status.get("name", "N/A"))
                ip = status.get("ip", "N/A")
                self.status_labels["ip"].config(text=ip)
                self.status_labels["type"].config(text=status.get("type", "N/A"))
                self.status_labels["lab_server"].config(text=status.get("lab_server", "N/A"))
                expires = status.get("expires_at", "N/A")
                if expires != "N/A":
                    try:
                        dt = datetime.strptime(expires, "%Y-%m-%d %H:%M:%S")
                        expires = dt.strftime("%d/%m/%Y %H:%M:%S")
                    except Exception as e:
                        self.log_to_console(f"Date format error: {str(e)}", "error")
                self.status_labels["expires_at"].config(text=expires)
                self.copy_ip_btn.state(['!disabled' if ip != "N/A" else 'disabled'])
                self.log_to_console("Status updated successfully")
            else:
                for label in self.status_labels.values():
                    label.config(text="N/A")
                self.copy_ip_btn.state(['disabled'])
                self.log_to_console("No active machine found", "warning")
        except Exception as e:
            self.log_to_console(f"Status check failed: {str(e)}", "error")
            messagebox.showerror("Error", f"Failed to check status: {str(e)}")

    def submit_flag(self):
        selected = self.machine_list.get()
        if not selected:
            messagebox.showerror("Error", "Select a machine first")
            return
        flag = self.flag_entry.get().strip()
        if not flag:
            messagebox.showerror("Error", "Enter a flag")
            return
        machine_id = self.machine_dict.get(selected)
        if submit_flag(machine_id, flag):
            self.log_to_console(f"Flag submitted for {selected}")
            self.flag_entry.delete(0, tk.END)
            messagebox.showinfo("Success", "Flag accepted!")
        else:
            self.log_to_console("Flag submission failed", "error")
            messagebox.showerror("Error", "Invalid flag")

if __name__ == "__main__":
    root = tk.Tk()
    app = HTBGUI(root)
    root.mainloop()
