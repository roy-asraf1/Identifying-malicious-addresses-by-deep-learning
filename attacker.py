import socket
import tkinter as tk
if __name__ == "__main__":


    HOST = "127.0.0.1"  # The server's hostname or IP address
    PORT = 65432  # The port used by the server

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(b"Hello, world")
        data = s.recv(1024)

    print(f"Received {data!r}")
    window = tk.Tk()
    greeting = tk.Label(text="hello attacker", font=("Arial"))
    window.mainloop()
    #learning()