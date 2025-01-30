import tkinter as tk
import time

"""
TODO:
- add user button
- when logged in, display main app layout
- design main app layout ( listview on left showing 
        websites of saved passwords, and frame on right
        with selected items details? )
- on main app layout, show which user is logged in, and way to log out
"""
class Password_Manager_GUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.geometry("1200x700")
        self.root.title("PassFraise")
        icon = tk.PhotoImage(file="assets/icon16x16.png")
        self.root.iconphoto(True, icon)
        
        # login
        self.login_frame = tk.Frame(self.root)
        self.username_login_entry = tk.Entry(self.login_frame, textvariable="username")
        self.password_login_entry = tk.Entry(self.login_frame, textvariable="password")
        self.submit_button = tk.Button(self.login_frame, text="Submit", command=self.submit_password)
        self.username_login_entry.pack()
        self.password_login_entry.pack()
        self.submit_button.pack()
        self.login_frame.pack()
        
        self.root.mainloop()

    def update_window(self):
        self.root.update()
    def submit_password(self):
        print("password submitted")


yes = Password_Manager_GUI()
