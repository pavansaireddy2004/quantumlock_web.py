# quantumlock_web.py
import streamlit as st
from pathlib import Path
import json, hashlib, secrets, re, os
from datetime import date

# -----------------------------
# Paths & "database"
# -----------------------------
BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "users.json"
FILES_ROOT = BASE_DIR / "user_files"
FILES_ROOT.mkdir(exist_ok=True)

# -----------------------------
# Helper functions (hashing, users)
# -----------------------------
def sha256_hex(text): return hashlib.sha256(text.encode()).hexdigest()
def hash_with_salt(secret, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt, sha256_hex(salt + secret)
def verify_with_salt(secret, salt, digest): return sha256_hex(salt + secret) == digest

def load_users():
    if not DB_PATH.exists(): return {}
    try: return json.loads(DB_PATH.read_text(encoding="utf-8"))
    except: return {}
def save_users(users): DB_PATH.write_text(json.dumps(users, indent=2), encoding="utf-8")

def username_exists(users, username): return any(username.lower() == u.lower() for u in users.keys())
def get_user(users, username):
    for k, v in users.items():
        if k.lower() == username.lower(): return k, v
    return None, None
def valid_username(username): return bool(re.fullmatch(r"[A-Za-z0-9_-]{3,20}", username))

def user_folder(username):
    folder = FILES_ROOT / username
    folder.mkdir(exist_ok=True, parents=True)
    return folder
def human_size(num_bytes):
    for unit in ["B","KB","MB","GB","TB"]:
        if num_bytes < 1024: return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PB"
def sanitize_filename(filename): return re.sub(r'[^A-Za-z0-9._-]', '_', filename)

# -----------------------------
# Password policy
# -----------------------------
PW_MIN_LEN = 12
def password_issues(pw):
    issues=[]
    if len(pw)<PW_MIN_LEN: issues.append(f"Password must be at least {PW_MIN_LEN} chars.")
    if not re.search(r"[A-Z]",pw): issues.append("Add uppercase letters.")
    if not re.search(r"[a-z]",pw): issues.append("Add lowercase letters.")
    if not re.search(r"\d",pw): issues.append("Add numbers.")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\+=/\\\$\$;'`~]",pw): issues.append("Add special chars.")
    return issues
def password_strength_score(pw):
    score=0
    if len(pw)>=PW_MIN_LEN: score+=1
    if re.search(r"[A-Z]",pw): score+=1
    if re.search(r"[a-z]",pw): score+=1
    if re.search(r"\d",pw): score+=1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\+=/\\\$\$;'`~]",pw): score+=1
    return score

# -----------------------------
# Streamlit page config
# -----------------------------
st.set_page_config(page_title="QuantumLock", page_icon="🔒", layout="centered")
st.title("🔒 QuantumLock — SafeVault")
st.caption("Next-gen secure locker (Demo)")

if "auth_user" not in st.session_state: st.session_state.auth_user = None
if "page" not in st.session_state: st.session_state.page = "home"

# -----------------------------
# Home Page
# -----------------------------
def show_homepage():
    st.image("https://i.imgur.com/7pXcJqG.png", width=120)  # Example logo
    st.header("Welcome to QuantumLock")
    st.write("Securely store your passwords, PINs, and important notes.")
    col1, col2 = st.columns(2)
    if col1.button("Create Account"): st.session_state.page="signup"
    if col2.button("Login"): st.session_state.page="signin"

# -----------------------------
# Signup Page
# -----------------------------
def show_signup():
    st.subheader("Create Account")
    first_name = st.text_input("First name")
    last_name = st.text_input("Last name")
    username = st.text_input("Username (unique)")
    pw = st.text_input("Password", type="password")
    pw2 = st.text_input("Confirm Password", type="password")

    if st.button("Create Account"):
        users = load_users()
        if not username or username_exists(users, username): st.error("Invalid or existing username")
        elif pw != pw2: st.error("Passwords do not match")
        else:
            salt, digest = hash_with_salt(pw)
            secret_code = secrets.token_urlsafe(8)
            sc_salt, sc_digest = hash_with_salt(secret_code)
            users[username] = {
                "profile":{"first_name":first_name,"last_name":last_name},
                "pw_salt":salt,"pw_hash":digest,
                "sc_salt":sc_salt,"sc_hash":sc_digest
            }
            save_users(users)
            st.success("Account created ✅")
            st.info(f"Save your Secret Code: {secret_code}")
            if st.button("Go to Login"): st.session_state.page="signin"

# -----------------------------
# Signin Page
# -----------------------------
def show_signin():
    st.subheader("Sign In")
    li_username = st.text_input("Username", key="li_user")
    li_password = st.text_input("Password", type="password", key="li_pw")
    li_secret = st.text_input("Secret Code", type="password", key="li_sc")
    if st.button("Sign In"):
        users = load_users()
        uname_key, user = get_user(users, li_username.strip())
        if not user: st.error("User not found")
        else:
            ok_pw = verify_with_salt(li_password, user["pw_salt"], user["pw_hash"])
            ok_sc = verify_with_salt(li_secret, user["sc_salt"], user["sc_hash"])
            if not ok_pw: st.error("Incorrect password")
            elif not ok_sc: st.error("Incorrect Secret Code")
            else:
                st.session_state.auth_user = uname_key
                st.success(f"Welcome, {user['profile']['first_name']}!")
                st.session_state.page="dashboard"

# -----------------------------
# Dashboard Page
# -----------------------------
def show_dashboard():
    st.header("🔐 Your Locker")
    st.caption("Upload and manage your files securely.")
    current_user = st.session_state.auth_user
    folder = user_folder(current_user)
    uploads = st.file_uploader("Upload files", accept_multiple_files=True)
    if uploads:
        for up in uploads:
            dest = folder / sanitize_filename(up.name)
            with open(dest, "wb") as f: f.write(up.getbuffer())
        st.success(f"Uploaded {len(uploads)} file(s).")
    all_files = sorted(folder.glob("*"))
    if not all_files: st.info("No files found. Upload something!")
    else:
        for fpath in all_files:
            st.write(f"- {fpath.name} ({human_size(fpath.stat().st_size)})")
            with open(fpath,"rb") as f:
                st.download_button("Download", data=f.read(), file_name=fpath.name)
            if st.button("Delete", key=f"del-{fpath.name}"):
                os.remove(fpath)
                st.experimental_rerun()
    if st.button("Sign Out"):
        st.session_state.auth_user=None
        st.session_state.page="home"

# -----------------------------
# Page Routing
# -----------------------------
if st.session_state.auth_user:
    show_dashboard()
else:
    if st.session_state.page=="home": show_homepage()
    elif st.session_state.page=="signup": show_signup()
    elif st.session_state.page=="signin": show_signin()
