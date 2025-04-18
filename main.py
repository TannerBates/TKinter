from tkinter import *
from tkinter import messagebox, filedialog
from PIL import Image, ImageTk
import mysql.connector
import bcrypt
import os
import tempfile

m = Tk()

# ----------------- Window Setup -----------------
window_width = 800
window_height = 500
screen_width = m.winfo_screenwidth()
screen_height = m.winfo_screenheight()
x = (screen_width // 2) - (window_width // 2)
y = (screen_height // 2) - (window_height // 2)
m.geometry(f"{window_width}x{window_height}+{x}+{y}")
m.title("Hello World")

# ----------------- Menu -----------------
menu = Menu(m)
m.config(menu=menu)
filemenu = Menu(menu)
menu.add_cascade(label="File", menu=filemenu)
filemenu.add_command(label="New")
filemenu.add_command(label="Open")
filemenu.add_command(label="Save")
filemenu.add_separator()
filemenu.add_command(label="Exit", command=m.quit)
editmenu = Menu(menu)
menu.add_cascade(label="Edit", menu=editmenu)
editmenu.add_command(label="Undo")
editmenu.add_command(label="Redo")
editmenu.add_separator()
helpmenu = Menu(menu)
menu.add_cascade(label="Help", menu=helpmenu)
helpmenu.add_command(label="About")

# ----------------- Frames -----------------
login_frame = Frame(m)
dashboard_frame = Frame(m)

m.rowconfigure(0, weight=1)
m.columnconfigure(0, weight=1)

for frame in (login_frame, dashboard_frame):
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
        messagebox.showerror("Error", "Username already exists.")
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
    username = username_entry.get()
    password = password_entry.get()

    db = connect_db()
    cursor = db.cursor()
    cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
    result = cursor.fetchone()
    db.close()

    if result and bcrypt.checkpw(password.encode('utf-8'), result[0].encode('utf-8')):
        messagebox.showinfo("Login", f"Welcome, {username}!")
        show_frame(dashboard_frame)
    else:
        messagebox.showerror("Login", "Invalid credentials.")

# ----------------- Login Frame Widgets -----------------
username_label = Label(login_frame, text="Username:")
username_label.pack(pady=10)

username_entry = Entry(login_frame)
username_entry.pack(pady=5)

password_label = Label(login_frame, text="Password:")
password_label.pack(pady=10)

password_entry = Entry(login_frame, show="*")
password_entry.pack(pady=5)

Button(login_frame, text="Register", command=register_user).pack(pady=5)
Button(login_frame, text="Login", command=validate_login).pack(pady=5)

# ----------------- Dashboard Layout -----------------
sidebar = Frame(dashboard_frame, bg="#2c3e50", width=150)
sidebar.pack(side=LEFT, fill=Y)

main_content = Frame(dashboard_frame, bg="#ecf0f1")
main_content.pack(side=RIGHT, fill=BOTH, expand=True)

dashboard_page = Frame(main_content, bg="#ecf0f1")
profile_page = Frame(main_content, bg="#ecf0f1")
settings_page = Frame(main_content, bg="#ecf0f1")

for page in (dashboard_page, profile_page, settings_page):
    page.place(relx=0, rely=0, relwidth=1, relheight=1)

def show_page(page):
    page.tkraise()

def logout():
    username_entry.delete(0, END)
    password_entry.delete(0, END)
    image_label.config(image="", text="No file uploaded.")
    show_frame(login_frame)

# Sidebar buttons
def add_sidebar_button(name, command):
    Button(sidebar, text=name, bg="#34495e", fg="white", font=('Arial', 11),
           relief="flat", command=command, padx=10, pady=10).pack(fill=X)


# ----------------- Profile Page Content -----------------

profile_pic_label = Label(profile_page, text="No profile picture uploaded.", bg="#ecf0f1", font=("Arial", 12))
profile_pic_label.pack(pady=10)

def upload_profile_picture():
    file_path = filedialog.askopenfilename(
        title="Select Profile Picture",
        filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.gif")]
    )
    if file_path:
        image = Image.open(file_path)
        image = image.resize((150, 150))
        photo = ImageTk.PhotoImage(image)
        profile_pic_label.config(image=photo, text="")
        profile_pic_label.image = photo

        # Optionally save profile picture to DB or local storage
        messagebox.showinfo("Profile Picture", "Profile picture updated successfully!")

Button(profile_page, text="Upload Profile Picture", command=upload_profile_picture).pack(pady=10)

# Display username from login
logged_in_username = StringVar()
Label(profile_page, text="Username:", font=("Arial", 12), bg="#ecf0f1").pack(pady=(20, 5))
Label(profile_page, textvariable=logged_in_username, font=("Arial", 12, "bold"), bg="#ecf0f1").pack()

# Password Reset Section
Label(profile_page, text="Reset Password", font=("Arial", 14, "bold"), bg="#ecf0f1").pack(pady=(30, 10))

new_password_entry = Entry(profile_page, show="*", width=30)
confirm_password_entry = Entry(profile_page, show="*", width=30)

Label(profile_page, text="New Password:", bg="#ecf0f1").pack()
new_password_entry.pack(pady=5)

Label(profile_page, text="Confirm Password:", bg="#ecf0f1").pack()
confirm_password_entry.pack(pady=5)

def reset_password():
    new_password = new_password_entry.get()
    confirm_password = confirm_password_entry.get()

    if new_password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match.")
        return
    if not new_password:
        messagebox.showerror("Error", "Password cannot be empty.")
        return

    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

    db = connect_db()
    cursor = db.cursor()
    try:
        cursor.execute("UPDATE users SET password = %s WHERE username = %s", (hashed_password, logged_in_username.get()))
        db.commit()
        messagebox.showinfo("Success", "Password updated successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to update password: {e}")
    finally:
        cursor.close()
        db.close()
        new_password_entry.delete(0, END)
        confirm_password_entry.delete(0, END)

Button(profile_page, text="Update Password", command=reset_password).pack(pady=10)


add_sidebar_button("Dashboard", lambda: show_page(dashboard_page))
add_sidebar_button("Profile", lambda: show_page(profile_page))
add_sidebar_button("Settings", lambda: show_page(settings_page))
add_sidebar_button("Logout", logout)

# ----------------- File Upload and Preview -----------------
uploaded_file = None
image_label = Label(dashboard_page, text="No file uploaded.", font=("Arial", 12), bg="#ecf0f1")

def upload_file():
    global uploaded_file
    file_path = filedialog.askopenfilename(title="Select a File", filetypes=[("All Files", "*.*"), ("Image Files", "*.png;*.jpg;*.jpeg;*.gif")])

    if file_path:
        uploaded_file = file_path
        file_name = os.path.basename(file_path)
        with open(file_path, 'rb') as file:
            file_data = file.read()

        db = connect_db()
        cursor = db.cursor()

        cursor.execute("INSERT INTO files (username, file_name, file_data) VALUES (%s, %s, %s)",
                       (username_entry.get(), file_name, file_data))
        db.commit()
        cursor.close()
        db.close()

        messagebox.showinfo("File Upload", f"File '{file_name}' uploaded successfully!")

        ext = os.path.splitext(file_name)[1].lower()
        if ext in ['.png', '.jpg', '.jpeg', '.gif']:
            image = Image.open(file_path)
            image = image.resize((200, 200))
            photo = ImageTk.PhotoImage(image)
            image_label.config(image=photo, text="")
            image_label.image = photo
        else:
            image_label.config(image='', text=f"File uploaded: {file_name}")

Button(dashboard_page, text="Upload File", command=upload_file).pack(pady=20)
image_label.pack(pady=10)

# ----------------- Start -----------------
show_frame(login_frame)
show_page(dashboard_page)

m.mainloop()
