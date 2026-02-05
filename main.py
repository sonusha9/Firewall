import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import subprocess
import datetime

log_file = "firewall_logs.txt"

def log_message(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        f.write(f"{timestamp} - {message}\n")

def add_rule():
    action = action_var.get()
    protocol = protocol_var.get()
    port = port_entry.get()
    if action and protocol and port:
        rule = f"-A INPUT -p {protocol} --dport {port} -j {action}"
        try:
            subprocess.run(f"sudo iptables {rule}", shell=True, check=True)
            messagebox.showinfo("Success", f"Rule added: {rule}")
            log_message(f"Rule added: {rule}")
            show_rules()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to add rule: {e}")
            log_message(f"Failed to add rule: {e}")
    else:
        messagebox.showwarning("Warning", "All fields must be filled out")
        log_message("Warning: All fields must be filled out")

def delete_rule():
    action = action_var.get()
    protocol = protocol_var.get()
    port = port_entry.get()
    if action and protocol and port:
        rule = f"-D INPUT -p {protocol} --dport {port} -j {action}"
        try:
            subprocess.run(f"sudo iptables {rule}", shell=True, check=True)
            messagebox.showinfo("Success", f"Rule deleted: {rule}")
            log_message(f"Rule deleted: {rule}")
            show_rules()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to delete rule: {e}")
            log_message(f"Failed to delete rule: {e}")
    else:
        messagebox.showwarning("Warning", "All fields must be filled out")
        log_message("Warning: All fields must be filled out")

def add_whitelist():
    ip = ip_entry.get()
    if ip:
        rule = f"-A INPUT -s {ip} -j ACCEPT"
        try:
            subprocess.run(f"sudo iptables {rule}", shell=True, check=True)
            messagebox.showinfo("Success", f"IP whitelisted: {ip}")
            log_message(f"IP whitelisted: {ip}")
            show_rules()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to whitelist IP: {e}")
            log_message(f"Failed to whitelist IP: {e}")
    else:
        messagebox.showwarning("Warning", "IP address must be provided")
        log_message("Warning: IP address must be provided")

def add_blacklist():
    ip = ip_entry.get()
    if ip:
        rule = f"-A INPUT -s {ip} -j DROP"
        try:
            subprocess.run(f"sudo iptables {rule}", shell=True, check=True)
            messagebox.showinfo("Success", f"IP blacklisted: {ip}")
            log_message(f"IP blacklisted: {ip}")
            show_rules()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to blacklist IP: {e}")
            log_message(f"Failed to blacklist IP: {e}")
    else:
        messagebox.showwarning("Warning", "IP address must be provided")
        log_message("Warning: IP address must be provided")

def delete_whitelist():
    ip = ip_entry.get()
    if ip:
        rule = f"-D INPUT -s {ip} -j ACCEPT"
        try:
            subprocess.run(f"sudo iptables {rule}", shell=True, check=True)
            messagebox.showinfo("Success", f"IP removed from whitelist: {ip}")
            log_message(f"IP removed from whitelist: {ip}")
            show_rules()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to remove IP from whitelist: {e}")
            log_message(f"Failed to remove IP from whitelist: {e}")
    else:
        messagebox.showwarning("Warning", "IP address must be provided")
        log_message("Warning: IP address must be provided")

def delete_blacklist():
    ip = ip_entry.get()
    if ip:
        rule = f"-D INPUT -s {ip} -j DROP"
        try:
            subprocess.run(f"sudo iptables {rule}", shell=True, check=True)
            messagebox.showinfo("Success", f"IP removed from blacklist: {ip}")
            log_message(f"IP removed from blacklist: {ip}")
            show_rules()
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to remove IP from blacklist: {e}")
            log_message(f"Failed to remove IP from blacklist: {e}")
    else:
        messagebox.showwarning("Warning", "IP address must be provided")
        log_message("Warning: IP address must be provided")

def show_rules():
    try:
        result = subprocess.run("sudo iptables -L", shell=True, check=True, capture_output=True, text=True)
        text_rules.delete(1.0, tk.END)
        parse_and_insert_rules(result.stdout)
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to show rules: {e}")
        log_message(f"Failed to show rules: {e}")

def parse_and_insert_rules(rules):
    lines = rules.splitlines()
    for line in lines:
        if "Chain" in line:
            text_rules.insert(tk.END, line + "\n", "chain")
        elif "target" in line:
            text_rules.insert(tk.END, line + "\n", "header")
        else:
            if "ACCEPT" in line:
                text_rules.insert(tk.END, line + "\n", "accept")
            elif "DROP" in line:
                text_rules.insert(tk.END, line + "\n", "drop")
            else:
                text_rules.insert(tk.END, line + "\n")

def flush_rules():
    try:
        subprocess.run("sudo iptables -F", shell=True, check=True)
        messagebox.showinfo("Success", "All rules flushed")
        log_message("All rules flushed")
        show_rules()
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Failed to flush rules: {e}")
        log_message(f"Failed to flush rules: {e}")

def show_help():
    help_text = """
    To add a rule:
    1. Select the action (ACCEPT/DROP).
    2. Select the protocol (TCP/UDP).
    3. Enter the port number.
    4. Click 'Add Rule' to apply the rule.

    To delete a rule:
    1. Select the action (ACCEPT/DROP).
    2. Select the protocol (TCP/UDP).
    3. Enter the port number.
    4. Click 'Delete Rule' to remove the rule.

    To view current rules:
    Click 'Show Rules'.

    To flush all rules:
    Click 'Flush Rules' to remove all rules.

    To whitelist an IP:
    1. Enter the IP address.
    2. Click 'Add to Whitelist' to whitelist the IP.
    3. Click 'Remove from Whitelist' to remove the IP from the whitelist.

    To blacklist an IP:
    1. Enter the IP address.
    2. Click 'Add to Blacklist' to blacklist the IP.
    3. Click 'Remove from Blacklist' to remove the IP from the blacklist.
    """
    messagebox.showinfo("Help", help_text)
    log_message("Help dialog opened")

def on_enter(e):
    e.widget['background'] = '#45a049'

def on_leave(e):
    e.widget['background'] = '#4caf50'

app = tk.Tk()
app.title("Firewall Configuration")
app.configure(bg='#f0f0f5')

style = ttk.Style()
style.configure('TButton', font=('Arial', 10, 'bold'), foreground='white', borderwidth='0')

frame = ttk.Frame(app, padding="10 10 10 10", relief='solid', borderwidth=2)
frame.pack(pady=10, padx=10)

action_var = tk.StringVar(value="ACCEPT")
protocol_var = tk.StringVar(value="tcp")

label_action = ttk.Label(frame, text="Action:", font=('Arial', 10, 'bold'))
label_action.grid(row=0, column=0, padx=5, pady=3, sticky='w')

option_action = ttk.OptionMenu(frame, action_var, "ACCEPT", "ACCEPT", "DROP")
option_action.grid(row=0, column=1, padx=5, pady=3)

label_protocol = ttk.Label(frame, text="Protocol:", font=('Arial', 10, 'bold'))
label_protocol.grid(row=1, column=0, padx=5, pady=3, sticky='w')

option_protocol = ttk.OptionMenu(frame, protocol_var, "tcp", "tcp", "udp")
option_protocol.grid(row=1, column=1, padx=5, pady=3)

label_port = ttk.Label(frame, text="Port:", font=('Arial', 10, 'bold'))
label_port.grid(row=2, column=0, padx=5, pady=3, sticky='w')

port_entry = ttk.Entry(frame, font=('Arial', 10))
port_entry.grid(row=2, column=1, padx=5, pady=3)

label_ip = ttk.Label(frame, text="IP Address:", font=('Arial', 10, 'bold'))
label_ip.grid(row=3, column=0, padx=5, pady=3, sticky='w')

ip_entry = ttk.Entry(frame, font=('Arial', 10))
ip_entry.grid(row=3, column=1, padx=5, pady=3)

button_frame = ttk.Frame(frame, padding="5 5 5 5")
button_frame.grid(row=4, column=0, columnspan=2, pady=5)

button_add = tk.Button(button_frame, text="Add Rule", command=add_rule, bg='#4caf50', width=12, height=1)
button_add.grid(row=0, column=0, padx=3, pady=3)
button_add.bind("<Enter>", on_enter)
button_add.bind("<Leave>", on_leave)

button_delete = tk.Button(button_frame, text="Delete Rule", command=delete_rule, bg='#f44336', width=12, height=1)
button_delete.grid(row=0, column=1, padx=3, pady=3)
button_delete.bind("<Enter>", on_enter)
button_delete.bind("<Leave>", on_leave)

button_show = tk.Button(button_frame, text="Show Rules", command=show_rules, bg='#2196f3', width=25, height=1)
button_show.grid(row=1, column=0, columnspan=2, pady=3)
button_show.bind("<Enter>", on_enter)
button_show.bind("<Leave>", on_leave)

button_flush = tk.Button(button_frame, text="Flush Rules", command=flush_rules, bg='#ff9800', width=25, height=1)
button_flush.grid(row=2, column=0, columnspan=2, pady=3)
button_flush.bind("<Enter>", on_enter)
button_flush.bind("<Leave>", on_leave)

button_help = tk.Button(button_frame, text="Help", command=show_help, bg='#9c27b0', width=25, height=1)
button_help.grid(row=3, column=0, columnspan=2, pady=3)
button_help.bind("<Enter>", on_enter)
button_help.bind("<Leave>", on_leave)

button_add_whitelist = tk.Button(button_frame, text="Add to Whitelist", command=add_whitelist, bg='#00bcd4', width=12, height=1)
button_add_whitelist.grid(row=4, column=0, padx=3, pady=3)
button_add_whitelist.bind("<Enter>", on_enter)
button_add_whitelist.bind("<Leave>", on_leave)

button_delete_whitelist = tk.Button(button_frame, text="Remove from Whitelist", command=delete_whitelist, bg='#00bcd4', width=18, height=1)
button_delete_whitelist.grid(row=4, column=1, padx=3, pady=3)
button_delete_whitelist.bind("<Enter>", on_enter)
button_delete_whitelist.bind("<Leave>", on_leave)

button_add_blacklist = tk.Button(button_frame, text="Add to Blacklist", command=add_blacklist, bg='#ff5722', width=12, height=1)
button_add_blacklist.grid(row=5, column=0, padx=3, pady=3)
button_add_blacklist.bind("<Enter>", on_enter)
button_add_blacklist.bind("<Leave>", on_leave)

button_delete_blacklist = tk.Button(button_frame, text="Remove from Blacklist", command=delete_blacklist, bg='#ff5722', width=18, height=1)
button_delete_blacklist.grid(row=5, column=1, padx=3, pady=3)
button_delete_blacklist.bind("<Enter>", on_enter)
button_delete_blacklist.bind("<Leave>", on_leave)

text_frame = ttk.Frame(app, padding="5 5 5 5", relief='solid', borderwidth=2)
text_frame.pack(pady=5, padx=10)

text_rules = tk.Text(text_frame, height=12, width=60, font=('Arial', 10))
text_rules.pack()

text_rules.tag_config("chain", foreground="#FF0000", font=("Arial", 10, "bold"))
text_rules.tag_config("header", foreground="#0000FF", font=("Arial", 10, "bold"))
text_rules.tag_config("accept", foreground="#008000", font=("Arial", 10, "bold"))
text_rules.tag_config("drop", foreground="#800000", font=("Arial", 10, "bold"))

show_rules()
app.mainloop()
