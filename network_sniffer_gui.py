import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP
import threading

# GUI Setup
def start_gui_sniffer():
    def packet_callback(packet):
        if IP in packet:
            ip_layer = packet[IP]
            proto = "Unknown"
            if TCP in packet:
                proto = "TCP"
            elif UDP in packet:
                proto = "UDP"
            elif ICMP in packet:
                proto = "ICMP"

            info = f"\n[+] Packet: {proto}\n"
            info += f"    From: {ip_layer.src}\n"
            info += f"    To:   {ip_layer.dst}\n"
            info += f"    Payload: {bytes(packet.payload)[:64]}\n"
            output_text.insert(tk.END, info)
            output_text.see(tk.END)

    def start_sniffing():
        try:
            sniff(prn=packet_callback, store=False)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start sniffing: {e}")

    def run_sniffer():
        start_btn.config(state=tk.DISABLED)
        stop_btn.config(state=tk.NORMAL)
        thread = threading.Thread(target=start_sniffing, daemon=True)
        thread.start()

    def stop_sniffer():
        messagebox.showinfo("Stop", "To stop sniffing, please close the application window.")

    def clear_output():
        output_text.delete(1.0, tk.END)

    # Main window
    window = tk.Tk()
    window.title("Advanced Network Sniffer")
    window.geometry("800x600")
    window.configure(bg="#0f172a")

    title = tk.Label(
        window,
        text="🛡️ Network Sniffer - Live Traffic Monitor",
        font=("Segoe UI", 18, "bold"),
        bg="#0f172a",
        fg="orange"
    )
    title.pack(pady=15)

    button_frame = tk.Frame(window, bg="#0f172a")
    button_frame.pack(pady=10)

    start_btn = tk.Button(
        button_frame,
        text="▶ Start Sniffing",
        command=run_sniffer,
        bg="#22c55e",
        fg="white",
        font=("Segoe UI", 12, "bold"),
        padx=15,
        pady=5
    )
    start_btn.grid(row=0, column=0, padx=10)

    stop_btn = tk.Button(
        button_frame,
        text="■ Stop",
        command=stop_sniffer,
        state=tk.DISABLED,
        bg="#ef4444",
        fg="white",
        font=("Segoe UI", 12, "bold"),
        padx=15,
        pady=5
    )
    stop_btn.grid(row=0, column=1, padx=10)

    clear_btn = tk.Button(
        button_frame,
        text="🧹 Clear",
        command=clear_output,
        bg="#3b82f6",
        fg="white",
        font=("Segoe UI", 12, "bold"),
        padx=15,
        pady=5
    )
    clear_btn.grid(row=0, column=2, padx=10)

    output_text = scrolledtext.ScrolledText(
        window,
        wrap=tk.WORD,
        font=("Consolas", 11),
        bg="#1e293b",
        fg="#e2e8f0",
        insertbackground="white",
        borderwidth=2,
        relief="solid"
    )
    output_text.pack(expand=True, fill="both", padx=15, pady=15)

    window.mainloop()

if __name__ == '__main__':
    start_gui_sniffer()
