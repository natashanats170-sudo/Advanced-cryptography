import tkinter as tk

def on_key(event=None):
    pwd = entry.get()
    res = analyze_password(pwd)
    entropy_label.config(text=f"Entropy: {res['entropy']} bits")
    verdict_label.config(text=res['verdict'])

root = tk.Tk()
root.title("Password Strength Analyzer")

tk.Label(root, text="Enter password:").pack(pady=5)
entry = tk.Entry(root, show="*", width=40)
entry.pack(pady=5)
entry.bind("<KeyRelease>", on_key)

entropy_label = tk.Label(root, text="Entropy: --")
entropy_label.pack()

verdict_label = tk.Label(root, text="", font=("Arial", 12, "bold"))
verdict_label.pack(pady=10)

root.mainloop()
