import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog
import socket
import subprocess
import threading

def is_port_open(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def get_service_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            try:
                s.sendall(b'\r\n')
            except:
                pass
            banner = s.recv(1024).decode(errors="ignore")
            return banner.strip() if banner else "Servis cevap vermedi"
    except:
        return "Servis okunamadı"

def scan_ports(ip, port_list, progress_callback=None):
    open_ports = []
    for idx, port in enumerate(port_list):
        if is_port_open(ip, port):
            banner = get_service_banner(ip, port)
            open_ports.append((port, banner))
        if progress_callback:
            progress_callback((idx + 1) / len(port_list) * 100)
    return open_ports

def guess_os(ip):
    try:
        cmd = f"ping -c 1 {ip}" if not is_windows() else f"ping -n 1 {ip}"
        result = subprocess.check_output(cmd, shell=True, text=True)
        for line in result.splitlines():
            if "ttl" in line.lower():
                for token in line.split():
                    if "ttl=" in token.lower():
                        ttl = int(token.split("=")[1])
                        if ttl >= 128:
                            return "Windows"
                        elif ttl >= 64:
                            return "Linux/Unix"
                        elif ttl >= 255:
                            return "Ağ Cihazı (Cisco)"
                        else:
                            return "Bilinmeyen OS"
        return "TTL değeri bulunamadı"
    except:
        return "İşletim Sistemi Tespit Edilemedi"

def is_windows():
    import platform
    return platform.system().lower() == "windows"

def resolve_domain(domain_or_ip):
    try:
        return socket.gethostbyname(domain_or_ip)
    except:
        return None

def update_progress(value):
    progress_bar['value'] = value
    root.update_idletasks()

def start_scan():
    user_input = ip_entry.get().strip()
    if not user_input:
        messagebox.showerror("Hata", "Lütfen bir IP adresi veya alan adı girin.")
        return

    output_box.delete('1.0', tk.END)
    update_progress(0)

    ip = resolve_domain(user_input)
    if ip is None:
        output_box.insert(tk.END, f" IP/Alan adı çözümlenemedi: {user_input}\n")
        update_progress(0)
        return

    output_box.insert(tk.END, f" '{user_input}' çözümlendi → IP: {ip}\n")
    output_box.insert(tk.END, f" Yaygın portlar taranıyor...\n")

    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 995, 3306, 8080]
    ports = scan_ports(ip, common_ports, progress_callback=update_progress)

    if ports:
        output_box.insert(tk.END, "\n Açık Portlar ve Servis Cevapları:\n")
        for port, banner in ports:
            output_box.insert(tk.END, f"  • Port {port:<5} → {banner}\n")
    else:
        output_box.insert(tk.END, "\n Açık port bulunamadı.\n")

    output_box.insert(tk.END, "\n İşletim Sistemi Tahmini...\n")
    os_guess = guess_os(ip)
    output_box.insert(tk.END, f" Tahmini OS: {os_guess}\n")

    update_progress(100)

def save_to_file():
    content = output_box.get("1.0", tk.END).strip()
    if not content:
        messagebox.showinfo("Bilgi", "Kaydedilecek bir tarama sonucu yok.")
        return

    filepath = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Metin Dosyası", "*.txt")],
        title="Sonuçları Kaydet"
    )

    if filepath:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        messagebox.showinfo("Başarılı", f"Sonuçlar başarıyla kaydedildi:\n{filepath}")

# GUI Arayüz
root = tk.Tk()
root.title("Port Tarayıcı + Banner Grab + OS Tahmini")
root.configure(bg="#E6CCFF")  # Lila arka plan

tk.Label(root, text="IP Adresi veya Alan Adı:", bg="#E6CCFF", font=("Arial", 11, "bold")).pack(pady=5)
ip_entry = tk.Entry(root, width=40, font=("Arial", 11))
ip_entry.pack()

tk.Button(root, text="Taramayı Başlat", command=lambda: threading.Thread(target=start_scan).start(),
          bg="#B266FF", fg="white", font=("Arial", 11, "bold")).pack(pady=10)

progress_bar = ttk.Progressbar(root, length=400, mode='determinate')
progress_bar.pack(pady=5)

output_box = scrolledtext.ScrolledText(root, width=80, height=20, font=("Courier", 10))
output_box.pack(padx=10, pady=10)

tk.Button(root, text="Sonuçları TXT Dosyasına Kaydet", command=save_to_file,
          bg="#9C27B0", fg="white", font=("Arial", 10, "bold")).pack(pady=5)

root.mainloop()
