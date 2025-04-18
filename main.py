import ttkbootstrap as ttkb
from tkinter import *
from tkinter import messagebox, filedialog
import mysql.connector
import bcrypt
import os
import json

# Global definition of theme_combobox
theme_combobox = None
current_user = None

# Function to save the selected theme to a file
def save_theme(selected_theme):
    with open("theme_settings.json", "w") as file:
        json.dump({"theme": selected_theme}, file)

# Function to load the selected theme from a file
def load_theme():
    if os.path.exists("theme_settings.json"):
        with open("theme_settings.json", "r") as file:
            theme_data = json.load(file)
            return theme_data.get("theme", "darkly")  # Default to "darkly" if no theme is saved
    return "darkly"  # Default theme if no theme settings file exists

def change_theme():
    selected_theme = theme_combobox.get()  # Get selected theme
    m.style.theme_use(selected_theme)  # Change the theme using ttkbootstrap method
    m.update_idletasks()  # Update the window to apply the changes
    save_theme(selected_theme)  # Save the selected theme to file

def start_app(selected_theme):
    global m, theme_combobox, current_user  # Declare global variables

    # Initialize ttkbootstrap Window
    m = ttkb.Window(themename=selected_theme)  # Using ttkbootstrap window

    # ----------------- Window Setup -----------------
    window_width = 800
    window_height = 500
    screen_width = m.winfo_screenwidth()
    screen_height = m.winfo_screenheight()

    x = (screen_width // 2) - (window_width // 2)
    y = (screen_height // 2) - (window_height // 2)
    m.geometry(f"{window_width}x{window_height}+{x}+{y}")
    m.title("Hello World")

    # ----------------- Frames -----------------
    login_frame = ttkb.Frame(m)
    dashboard_frame = ttkb.Frame(m)
    profile_frame = ttkb.Frame(m)
    settings_frame = ttkb.Frame(m)
    messages_frame = ttkb.Frame(m)

    m.rowconfigure(0, weight=1)
    m.columnconfigure(0, weight=1)

    for frame in (login_frame, dashboard_frame, profile_frame, settings_frame, messages_frame):
        frame.grid(row=0, column=0, sticky='nsew')

    def show_frame(frame):
        frame.tkraise()

    # ----------------- Database Connection -----------------
    def connect_db():
        return mysql.connector.connect(
            host="localhost",
            user="tkinter",
            password="JBq-tbdObGrWkrqg",
            database="tkinter",
        )

    # ----------------- Register -----------------
    def register_user():
        username = username_entry.get()
        password = password_entry.get()

        if not username or not password:
            messagebox.showerror("Input Error", "Username and Password cannot be empty.")
            return

        db = connect_db()
        cursor = db.cursor()

        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            messagebox.showerror("Error", "Username already exists. Please choose another.")
            cursor.close()
            db.close()
            return

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
            db.commit()
            messagebox.showinfo("Success", "User registered successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
        finally:
            cursor.close()
            db.close()

    # ----------------- Login -----------------
    def validate_login():
        global current_user
        username = username_entry.get()
        password = password_entry.get()

        db = connect_db()
        cursor = db.cursor()
        cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()
        db.close()

        if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
            messagebox.showinfo("Login", f"Welcome, {username}!")
            current_user = username
            show_frame(dashboard_frame)
            show_page(dashboard_page)
            load_profile()
        else:
            messagebox.showerror("Login", "Invalid credentials.")

    username_label = ttkb.Label(login_frame, text="Username:")
    username_label.pack(pady=10)

    username_entry = ttkb.Entry(login_frame, width=30)
    username_entry.pack(pady=5)

    password_label = ttkb.Label(login_frame, text="Password:")
    password_label.pack(pady=10)

    password_entry = ttkb.Entry(login_frame, show="*", width=30)
    password_entry.pack(pady=5)

    ttkb.Button(login_frame, text="Login", command=validate_login).pack(pady=5)

    sidebar = ttkb.Frame(dashboard_frame, width=150, bootstyle="dark")
    sidebar.pack(side=LEFT, fill=Y)

    main_content = ttkb.Frame(dashboard_frame, bootstyle="light")
    main_content.pack(side=RIGHT, fill=BOTH, expand=True)

    dashboard_page = ttkb.Frame(main_content)
    profile_page = ttkb.Frame(main_content)
    settings_page = ttkb.Frame(main_content)

    for page in (dashboard_page, profile_page, settings_page):
        page.place(relx=0, rely=0, relwidth=1, relheight=1)

    def show_page(page):
        page.tkraise()

    def logout():
        username_entry.delete(0, END)
        password_entry.delete(0, END)
        show_frame(login_frame)

    def add_sidebar_button(name, command):
        ttkb.Button(sidebar, text=name, bootstyle="dark", command=command, width=20).pack(pady=10)

    add_sidebar_button("Dashboard", lambda: show_page(dashboard_page))
    add_sidebar_button("Profile", lambda: show_page(profile_page))
    add_sidebar_button("Settings", lambda: show_page(settings_page))
    add_sidebar_button("Messages", lambda: show_frame(messages_frame))
    add_sidebar_button("Logout", logout)

    def load_profile():
        global current_user
        db = connect_db()
        cursor = db.cursor()
        cursor.execute("SELECT username FROM users WHERE username = %s", (current_user,))
        user_data = cursor.fetchone()
        db.close()

        if user_data:
            profile_username_label.config(text=f"Username: {user_data[0]}")
            profile_picture_label.config(text="Profile Picture: Not Available")

    def change_password():
        def submit_new_password():
            old_password = old_password_entry.get()
            new_password = new_password_entry.get()
            confirm_password = confirm_password_entry.get()

            username = current_user
            db = connect_db()
            cursor = db.cursor()
            cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
            result = cursor.fetchone()

            if result and bcrypt.checkpw(old_password.encode('utf-8'), result[0].encode('utf-8')):
                if new_password == confirm_password:
                    hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                    cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_new_password, username))
                    db.commit()
                    messagebox.showinfo("Success", "Password changed successfully!")
                    change_password_window.destroy()
                else:
                    messagebox.showerror("Error", "New password and confirmation do not match.")
            else:
                messagebox.showerror("Error", "Incorrect old password.")
            db.close()

        change_password_window = Toplevel(m)
        change_password_window.title("Change Password")
        window_w, window_h = 400, 300
        x = (m.winfo_screenwidth() // 2) - (window_w // 2)
        y = (m.winfo_screenheight() // 2) - (window_h // 2)
        change_password_window.geometry(f"{window_w}x{window_h}+{x}+{y}")

        ttkb.Label(change_password_window, text="Old Password:").pack(pady=5)
        old_password_entry = ttkb.Entry(change_password_window, show="*")
        old_password_entry.pack(pady=5)

        ttkb.Label(change_password_window, text="New Password:").pack(pady=5)
        new_password_entry = ttkb.Entry(change_password_window, show="*")
        new_password_entry.pack(pady=5)

        ttkb.Label(change_password_window, text="Confirm New Password:").pack(pady=5)
        confirm_password_entry = ttkb.Entry(change_password_window, show="*")
        confirm_password_entry.pack(pady=5)

        ttkb.Button(change_password_window, text="Submit", command=submit_new_password).pack(pady=20)

    ttkb.Label(profile_page, text="Profile", font=("Arial", 14)).pack(pady=20)
    profile_username_label = ttkb.Label(profile_page, text="Username: Not Available", font=("Arial", 12))
    profile_username_label.pack(pady=10)
    profile_picture_label = ttkb.Label(profile_page, text="Profile Picture: Not Available", font=("Arial", 12))
    profile_picture_label.pack(pady=10)
    ttkb.Button(profile_page, text="Change Password", command=change_password).pack(pady=10)

    # ----------------- Messages Page -----------------
    # Add sidebar and main content to messages_frame
    messages_sidebar = ttkb.Frame(messages_frame, width=150)
    messages_sidebar.pack(side=LEFT, fill=Y)

    messages_main_content = ttkb.Frame(messages_frame)
    messages_main_content.pack(side=RIGHT, fill=BOTH, expand=True)

    # Add same sidebar buttons for consistency
    def add_messages_sidebar_button(name, command):
        ttkb.Button(messages_sidebar, text=name, command=command, width=20).pack(pady=10)

    add_messages_sidebar_button("Dashboard", lambda: show_frame(dashboard_frame))
    add_messages_sidebar_button("Profile", lambda: show_page(profile_page))
    add_messages_sidebar_button("Settings", lambda: show_page(settings_page))
    add_messages_sidebar_button("Messages", lambda: show_frame(messages_frame))
    add_messages_sidebar_button("Logout", logout)

    # Main content widgets
    ttkb.Label(messages_main_content, text="Send a Message", font=("Arial", 14)).pack(pady=10)

    recipient_entry = ttkb.Entry(messages_main_content, width=30)
    recipient_entry.pack(pady=5)
    recipient_entry.insert(0, "Recipient Username")

    message_entry = Text(messages_main_content, height=4, width=40)
    message_entry.pack(pady=5)

    def send_message():
        recipient = recipient_entry.get()
        message = message_entry.get("1.0", END).strip()
        if recipient and message:
            db = connect_db()
            cursor = db.cursor()
            cursor.execute("INSERT INTO messages (sender, recipient, message) VALUES (%s, %s, %s)", (current_user, recipient, message))
            db.commit()
            cursor.close()
            db.close()
            messagebox.showinfo("Message", "Message sent successfully!")
            message_entry.delete("1.0", END)
        else:
            messagebox.showerror("Error", "Both recipient and message are required.")

    ttkb.Button(messages_main_content, text="Send", command=send_message).pack(pady=10)

    # ----------------- Theme Change in Settings -----------------
    theme_label = ttkb.Label(settings_page, text="Choose Theme:", font=("Arial", 12))
    theme_label.pack(pady=10)

    themes = ["darkly", "flatly", "superhero", "cosmo", "cerulean", "lux", "minty", "solar", "sandstone"]
    theme_combobox = ttkb.Combobox(settings_page, values=themes, state="readonly", bootstyle="light")
    theme_combobox.set(selected_theme)
    theme_combobox.pack(pady=10)

    apply_button = ttkb.Button(settings_page, text="Apply Theme", command=change_theme)
    apply_button.pack(pady=10)

    show_frame(login_frame)
    m.mainloop()

start_app(load_theme())
