from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3, os, json, base64, qrcode, random, time, re
from crypto_utils import *
from acl import check_access

app = Flask(__name__)
app.secret_key = "strong_secret_key"   # Required for flash messages
DB = "database.db"

# =====================================================
# PASSWORD POLICY ENFORCEMENT
# =====================================================
def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*()_+=\-{}[\]:;\"'<>,.?/]", password):
        return False
    return True


# =====================================================
# DATABASE INITIALIZATION
# =====================================================
def init_db():
    with sqlite3.connect(DB) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY,
            email TEXT,
            phone TEXT,
            role TEXT,
            salt BLOB,
            password_hash BLOB
        )""")

        con.execute("""CREATE TABLE IF NOT EXISTS otp_store(
            username TEXT,
            otp TEXT,
            timestamp INTEGER
        )""")

        con.execute("""CREATE TABLE IF NOT EXISTS visits(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            visitor TEXT,
            purpose TEXT,
            status TEXT,
            encrypted_data BLOB,
            signature BLOB,
            qr_path TEXT
        )""")

    create_default_admin()


# =====================================================
# PRE-REGISTERED ADMIN
# =====================================================
def create_default_admin():
    with sqlite3.connect(DB) as con:
        admin = con.execute(
            "SELECT * FROM users WHERE role='admin'"
        ).fetchone()

        if not admin:
            salt = os.urandom(16)
            pwd_hash = hash_password("Admin@123", salt)
            con.execute(
                "INSERT INTO users VALUES (?,?,?,?,?,?)",
                ("admin", "admin@visage.com", "9999999999",
                 "admin", salt, pwd_hash)
            )

init_db()


@app.route("/")
def index():
    return render_template("index.html")


# =====================================================
# USER REGISTRATION (ALERT ON SAME PAGE)
# =====================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        phone = request.form["phone"]
        password = request.form["password"]
        role = request.form["role"]

        # Strong password validation
        if not is_strong_password(password):
            flash(
                "Password must be at least 8 characters long and include "
                "uppercase, lowercase, number, and special character"
            )
            return redirect(url_for("register"))

        salt = os.urandom(16)
        pwd_hash = hash_password(password, salt)

        with sqlite3.connect(DB) as con:
            con.execute(
                "INSERT INTO users VALUES (?,?,?,?,?,?)",
                (username, email, phone, role, salt, pwd_hash)
            )

        flash("Registration successful. Please login.")
        return redirect(url_for("login"))

    return render_template("register.html")


# =====================================================
# LOGIN – STEP 1 (SFA + ALERT)
# =====================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        with sqlite3.connect(DB) as con:
            user = con.execute(
                "SELECT phone, role, salt, password_hash FROM users WHERE username=?",
                (username,)
            ).fetchone()

        if not user or not verify_password(password, user[2], user[3]):
            flash("Invalid username or password")
            return redirect(url_for("login"))

        otp = str(random.randint(100000, 999999))
        print(f"[SIMULATED SMS] OTP for {user[0]} : {otp}")

        with sqlite3.connect(DB) as con:
            con.execute("DELETE FROM otp_store WHERE username=?", (username,))
            con.execute(
                "INSERT INTO otp_store VALUES (?,?,?)",
                (username, otp, int(time.time()))
            )

        return render_template("login.html", otp_stage=True, username=username)

    return render_template("login.html", otp_stage=False)


# =====================================================
# LOGIN – STEP 2 (OTP ALERT)
# =====================================================
@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    username = request.form["username"]
    otp_entered = request.form["otp"]

    with sqlite3.connect(DB) as con:
        record = con.execute(
            "SELECT otp, timestamp FROM otp_store WHERE username=?",
            (username,)
        ).fetchone()
        role = con.execute(
            "SELECT role FROM users WHERE username=?",
            (username,)
        ).fetchone()[0]

    if not record:
        flash("OTP not found")
        return redirect(url_for("login"))

    if time.time() - record[1] > 300:
        flash("OTP expired")
        return redirect(url_for("login"))

    if otp_entered != record[0]:
        flash("Invalid OTP")
        return redirect(url_for("login"))

    if role == "visitor":
        return redirect(url_for("visitor", user=username))
    elif role == "host":
        return redirect(url_for("host"))
    else:
        return redirect(url_for("admin"))


# =====================================================
# VISITOR MODULE
# =====================================================
@app.route("/visitor", methods=["GET", "POST"])
def visitor():
    username = request.args.get("user")

    if request.method == "POST":
        purpose = request.form["purpose"]

        with sqlite3.connect(DB) as con:
            con.execute("""
                INSERT INTO visits
                (visitor, purpose, status, encrypted_data, signature, qr_path)
                VALUES (?,?,?,?,?,?)
            """, (username, purpose, "PENDING", None, None, None))

        flash("Visit request submitted")
        return redirect(url_for("visitor", user=username))

    with sqlite3.connect(DB) as con:
        visit = con.execute("""
            SELECT status, qr_path
            FROM visits
            WHERE visitor=?
            ORDER BY id DESC
            LIMIT 1
        """, (username,)).fetchone()

    return render_template("visitor.html", visit=visit, username=username)


# =====================================================
# HOST MODULE
# =====================================================
@app.route("/host", methods=["GET", "POST"])
def host():
    with sqlite3.connect(DB) as con:
        visits = con.execute(
            "SELECT id, visitor, purpose, status FROM visits"
        ).fetchall()

    if request.method == "POST":
        visit_id = request.form["visit_id"]

        with sqlite3.connect(DB) as con:
            visitor, purpose = con.execute(
                "SELECT visitor, purpose FROM visits WHERE id=?",
                (visit_id,)
            ).fetchone()
            
            # encrypting using aes
            payload = json.dumps({
                "visit_id": visit_id,
                "visitor": visitor,
                "purpose": purpose,
                "status": "APPROVED",
                "issued_at": int(time.time()),
                "issuer": "VISAGE"
            }).encode()

            aes_key = os.urandom(32)
            encrypted = encrypt_data(payload, aes_key)

            private_key, _ = generate_rsa_keys()
            
            # signing using rsa
            signature = sign_data(encrypted, private_key)

            qr_data = base64.b64encode(encrypted).decode()
            qr_path = f"static/qr_visit_{visit_id}.png"
            img = qrcode.make(qr_data)
            img.save(qr_path)

            con.execute("""
                UPDATE visits
                SET status='APPROVED',
                    encrypted_data=?,
                    signature=?,
                    qr_path=?
                WHERE id=?
            """, (encrypted, signature, qr_path, visit_id))

        flash("Visit approved and QR generated")
        return redirect(url_for("host"))

    return render_template("host.html", visits=visits)


# =====================================================
# ADMIN MODULE (ACL ENFORCED)
# =====================================================
@app.route("/admin")
def admin():
    if not check_access("admin", "view_users"):
        flash("Unauthorized access")
        return redirect(url_for("login"))

    with sqlite3.connect(DB) as con:
        users = con.execute(
            "SELECT username, email, phone, role FROM users"
        ).fetchall()

    return render_template("admin.html", users=users)


if __name__ == "__main__":
    app.run(debug=True)
