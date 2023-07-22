import tkinter as tk
from threading import Thread, Event
import capture
import sys

# Custom class representing a text box that effectively replaces the terminal for standard output.
class RedirectedText(tk.Text):
    def __init__(self, *args, **kwargs):
        tk.Text.__init__(self, *args, **kwargs)
        self.line_limit = 1000
        self.running = True
        self.stop_event = Event()

    def write(self, text):
        if self.running:
            self.insert(tk.END, text)
            self.see(tk.END)
            self.check_line_limit()

    def check_line_limit(self):
        lines = int(self.index('end-1c').split('.')[0])
        if lines > self.line_limit:
            self.delete("1.0", f"{lines - self.line_limit}.0")

    def flush(self):
        pass

root = tk.Tk()

root.geometry("800x500")
root.title("Packet Capture Window")

packet_label = tk.Label(root, text="Packet:", font=("Arial",12))
packet_label.pack()

#packet_text = tk.Text(root, height=50, width=80, font=("Arial", 18))
packet_text = RedirectedText(root, height=15, width=100, font=("Arial", 18))
packet_text.pack()

sys.stdout = packet_text # Redirects the standard output from the terminal to the GUI.

'''def update_packet_text(packet):
    packet_text.insert(tk.END, packet + "\n\n")'''

def handle_packet_with_gui(packet):
    # Calls the handle_packet function from capture.py.
    capture.handle_packet(packet)
    #update_packet_text(str(packet))

def packet_capture_thread():
    #capture.sniff(prn=handle_packet_with_gui)
    capture.main()
    

def start_capture():
    packet_text.running = True
    
    packet_text.stop_event.clear()
    packet_capture_thread
    #capture_thread = Thread(target=packet_capture_thread)
    #capture_thread.start()


def stop_capture():
    packet_text.running = False
    packet_text.stop_event.set()

start_btn = tk.Button(root, text="Start Capture", command=start_capture, font=("Arial",12))
start_btn.pack()

stop_btn = tk.Button(root, text="Stop Capture", command=stop_capture, font=("Arial",12))
stop_btn.pack()

capture_thread = Thread(target=packet_capture_thread)
capture_thread.daemon = True
capture_thread.start()

root.mainloop()
