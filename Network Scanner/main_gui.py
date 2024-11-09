# main_gui.py
import tkinter as tk
from tkinter import scrolledtext, ttk
from network_mapping_gui import detect_os, detect_services, format_service_info, scan_network
from database import insert_scan_result
import ipaddress
import logging
import sys
import warnings

logging.basicConfig(level=logging.INFO, format='%(message)s')

SCAN_TYPES = {
    'SYN Scan': '-sS',
    'Connect Scan': '-sT',
    'UDP Scan': '-sU',
    'FIN Scan': '-sF',
    'Xmas Scan': '-sX',
    'Null Scan': '-sN',
    'ACK Scan': '-sA',
    'Window Scan': '-sW',
    'Maimon Scan': '-sM',
    'Idle Scan': '-sI',
    'RPC Scan': '-sR',
    'SCTP INIT Scan': '-sY',
    'SCTP COOKIE ECHO Scan': '-sZ',
    'IP Protocol Scan': '-sO',
    'FTP Bounce Scan': '-b',
    'No Ping Scan': '-Pn'
}

def scan():
    ip_input = ip_entry.get()
    scan_type_name = scan_type_var.get()
    scan_type = SCAN_TYPES.get(scan_type_name, '-sS')
    scan_network(ip_input, scan_type, output_area)

def create_gradient(canvas, width, height, color1, color2):
    (r1, g1, b1) = canvas.winfo_rgb(color1)
    (r2, g2, b2) = canvas.winfo_rgb(color2)
    r_ratio = float(r2 - r1) / height
    g_ratio = float(g2 - g1) / height
    b_ratio = float(b2 - b1) / height

    for i in range(height):
        nr = int(r1 + (r_ratio * i))
        ng = int(g1 + (g_ratio * i))
        nb = int(b1 + (b_ratio * i))
        color = "#%4.4x%4.4x%4.4x" % (nr, ng, nb)
        canvas.create_line(0, i, width, i, tags=("gradient",), fill=color)
    canvas.lower("gradient")

class TextRedirector(object):
    def __init__(self, widget):
        self.widget = widget

    def write(self, string):
        self.widget.insert(tk.END, string)
        self.widget.see(tk.END)  # Auto-scroll to the end

    def flush(self):
        pass

def handle_warning(message, category, filename, lineno, file=None, line=None):
    sys.stderr.write(f"{category.__name__}: {message}\n")

warnings.showwarning = handle_warning

app = tk.Tk()
app.title("Network Scanner")
app.geometry("600x400")
app.resizable(True, True)

canvas = tk.Canvas(app, height=400, width=600)
canvas.pack(fill="both", expand=True)
create_gradient(canvas, 600, 400, 'blue', 'black')

customFont = ('Helvetica', 14, 'bold')

label_ip = tk.Label(app, text="IP Address:", font=customFont, bg='light blue', pady=1)
label_ip.place(x=50, y=50)
ip_entry = tk.Entry(app, font=customFont, bd=2, relief=tk.FLAT)
ip_entry.place(x=200, y=50)

label_scan = tk.Label(app, text="Scan Type:", font=customFont, bg='light blue', pady=1)
label_scan.place(x=50, y=100)
scan_type_var = tk.StringVar(value='SYN Scan')
scan_type_dropdown = ttk.Combobox(app, textvariable=scan_type_var, font=customFont)
scan_type_dropdown['values'] = list(SCAN_TYPES.keys())
scan_type_dropdown.place(x=200, y=100)

style = ttk.Style()
style.configure('W.TButton', font=('Calibri', 12, 'bold'), foreground='black', background='light blue')
style.map('W.TButton', foreground=[('active', '!disabled', 'green'), ('pressed', 'red')], background=[('active', 'black')])
scan_button = ttk.Button(app, text="Scan", style='W.TButton', command=scan)
scan_button.place(x=250, y=150)

outputFont = ('Helvetica', 12)
output_area = scrolledtext.ScrolledText(app, font=outputFont, bd=2, relief=tk.GROOVE)
output_area.place(x=50, y=200, width=500, height=150)

# Redirect stdout and stderr
sys.stdout = TextRedirector(output_area)
sys.stderr = TextRedirector(output_area)

# Now, all print statements and errors will be redirected to the output_area in the GUI.

app.mainloop()