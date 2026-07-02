import argparse
import sys
import tkinter as tk
from tkinter import messagebox, scrolledtext
from analyzer import analyze, suggest_password

def launch_gui():
    def check_password():
        pwd = entry.get()
        if not pwd:
            messagebox.showwarning("Warning", "Please enter a password!")
            return
        result = analyze(pwd)
        strength_label.config(text=f"Strength: {result['strength']}")
        entropy_label.config(text=f"Entropy: {result['entropy']} bits")
        crack_label.config(text=f"Crack Time: {result['crack_time']}")
        score_label.config(text=f"Score: {result['score']} / 10 ({result['score_percent']}%)")
        tips_text.config(state=tk.NORMAL)
        tips_text.delete("1.0", tk.END)
        if result["tips"]:
            for tip in result["tips"]:
                tips_text.insert(tk.END, f"- {tip}\n")
        else:
            tips_text.insert(tk.END, "Your password looks excellent!\n")
        tips_text.config(state=tk.DISABLED)
        suggestions_text.config(state=tk.NORMAL)
        suggestions_text.delete("1.0", tk.END)
        if result["suggestions"]:
            for s in result["suggestions"]:
                suggestions_text.insert(tk.END, f"{s}\n")
        else:
            suggestions_text.insert(tk.END, "No suggestions needed.")
        suggestions_text.config(state=tk.DISABLED)

    def generate_password():
        new_pass = suggest_password()
        entry.delete(0, tk.END)
        entry.insert(0, new_pass)
        check_password()

    def copy_suggestion():
        text = None
        suggestions = suggestions_text.get("1.0", tk.END).strip().splitlines()
        if suggestions and suggestions[0] and suggestions[0] != "No suggestions needed.":
            text = suggestions[0]
        else:
            text = entry.get()
        if not text:
            messagebox.showinfo("Copy", "Nothing to copy.")
            return
        root.clipboard_clear()
        root.clipboard_append(text)
        messagebox.showinfo("Copy", "Password copied to clipboard (temporarily).")

    root = tk.Tk()
    root.title("Password Strength Analyzer")
    root.geometry("520x560")
    root.resizable(False, False)
    tk.Label(root, text="Password Strength Analyzer", font=("Arial", 16, "bold")).pack(pady=10)
    frame_input = tk.Frame(root)
    frame_input.pack(pady=5)
    tk.Label(frame_input, text="Enter Password").grid(row=0, column=0, sticky="w")
    entry = tk.Entry(frame_input, show="*", width=36, font=("Arial", 12))
    entry.grid(row=1, column=0, padx=(0,10))
    btn_frame = tk.Frame(frame_input)
    btn_frame.grid(row=1, column=1, sticky="n")
    tk.Button(btn_frame, text="Analyze", width=14, command=check_password).pack(pady=(0,6))
    tk.Button(btn_frame, text="Generate Strong Password", width=14, command=generate_password).pack()
    result_frame = tk.Frame(root)
    result_frame.pack(pady=10)
    strength_label = tk.Label(result_frame, text="Strength: ", font=("Arial", 12))
    strength_label.pack()
    entropy_label = tk.Label(result_frame, text="Entropy: ", font=("Arial", 12))
    entropy_label.pack()
    crack_label = tk.Label(result_frame, text="Crack Time: ", font=("Arial", 12))
    crack_label.pack()
    score_label = tk.Label(result_frame, text="Score: ", font=("Arial", 12))
    score_label.pack()
    tk.Label(root, text="Suggestions / Generated Passwords", font=("Arial", 12, "bold")).pack(pady=(10,0))
    suggestions_text = scrolledtext.ScrolledText(root, height=6, width=60, state=tk.DISABLED)
    suggestions_text.pack(pady=(2,8))
    copy_btn = tk.Button(root, text="Copy Top Suggestion / Current Password", command=copy_suggestion)
    copy_btn.pack(pady=(0,8))
    tk.Label(root, text="Actionable Tips", font=("Arial", 12, "bold")).pack(pady=(6,0))
    tips_text = scrolledtext.ScrolledText(root, height=8, width=60, state=tk.DISABLED)
    tips_text.pack(pady=(2,8))
    tk.Label(root, text="Tip: Generated passwords are copied to clipboard temporarily; store them securely.", font=("Arial", 9)).pack(pady=(6,4))
    root.mainloop()

def launch_cli(password: str, suggest_flag: bool = False):
    result = analyze(password)
    print("\n🔐 Password Strength Analysis 🔐\n")
    print(f"Length      : {result['length']}")
    print(f"Has Upper   : {result['has_upper']}")
    print(f"Has Lower   : {result['has_lower']}")
    print(f"Has Digits  : {result['has_digits']}")
    print(f"Has Symbols : {result['has_symbols']}")
    print(f"Entropy     : {result['entropy']} bits")
    print(f"Strength    : {result['strength']}")
    print(f"Crack Time  : {result['crack_time']}")
    print(f"Score       : {result['score']} / 10 ({result['score_percent']}%)")
    if result["tips"]:
        print("\nSuggestions:")
        for tip in result["tips"]:
            print(f"- {tip}")
    else:
        print("\nYour password looks excellent! 🎉")
    if suggest_flag or result["strength"] in ("Weak", "Medium"):
        print("\nSuggested strong passwords:")
        count = 3 if suggest_flag else 1
        for _ in range(count):
            print(f"- {suggest_password()}")

def main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer (CLI + GUI)")
    parser.add_argument("-p", "--password", help="Password to analyze (CLI mode)")
    parser.add_argument("--gui", action="store_true", help="Launch GUI interface")
    parser.add_argument("--suggest", action="store_true", help="When used with -p, print multiple suggested passwords")
    args = parser.parse_args()
    if args.gui:
        launch_gui()
    elif args.password:
        launch_cli(args.password, suggest_flag=args.suggest)
    else:
        print("\nNo mode selected. Try:\n")
        print("CLI : python app.py -p MyPass@123")
        print("CLI with suggestions : python app.py -p weakpass --suggest")
        print("GUI : python app.py --gui\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
