from tkinter import *
from tkinter import messagebox, filedialog
from PIL import Image, ImageTk  # Install Pillow for image handling
import mysql.connector
import bcrypt
import os

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
        user="user",
        password="password",
        database="database",
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

    # Check if user already exists
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

# Sub-pages inside main_content
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
    show_frame(login_frame)

# Sidebar buttons
def add_sidebar_button(name, command):
    Button(sidebar, text=name, bg="#34495e", fg="white", font=('Arial', 11),
           relief="flat", command=command, padx=10, pady=10).pack(fill=X)

add_sidebar_button("Dashboard", lambda: show_page(dashboard_page))
add_sidebar_button("Profile", lambda: show_page(profile_page))
add_sidebar_button("Settings", lambda: show_page(settings_page))
add_sidebar_button("Logout", logout)

# ----------------- File Upload -----------------
uploaded_file = None
image_label = Label(dashboard_page, text="No file uploaded.", font=("Arial", 12))

def upload_file():
    global uploaded_file
    file_path = filedialog.askopenfilename(title="Select a File", filetypes=[("All Files", "*.*"), ("Image Files", "*.png;*.jpg;*.jpeg;*.gif")])

    if file_path:
        uploaded_file = file_path
        # Preview image if it is an image
        if uploaded_file.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
            image = Image.open(uploaded_file)
            image = image.resize((200, 200))  # Resize the image for preview
            photo = ImageTk.PhotoImage(image)
            image_label.config(image=photo, text="")
            image_label.image = photo  # Keep a reference to avoid garbage collection
        else:
            image_label.config(image='', text="File uploaded: " + os.path.basename(uploaded_file))
        image_label.pack(pady=20)

Button(dashboard_page, text="Upload File", command=upload_file).pack(pady=20)
image_label.pack(pady=10)

# ----------------- Start with login -----------------
show_frame(login_frame)
show_page(dashboard_page)

m.mainloop()
