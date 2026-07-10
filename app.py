from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt
import json
import threading
import time
from datetime import datetime
import smtplib
from email.mime.text import MIMEText

# Detection Engines
from detection_engine import detect_attack
from detect_system_application import detect_system_event,detect_application_event

try:
    import win32evtlog
    WINDOWS_AVAILABLE=True
except:
    WINDOWS_AVAILABLE=False

app=Flask(__name__)
app.secret_key="watchdog_secret_key"

# EMAIL CONFIG
EMAIL_ADDRESS = "kadamaishwarya282@gmail.com"
EMAIL_PASSWORD = "bbxp jwzv sbjn umkh"

def send_email(receiver_email, subject, body):
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_ADDRESS
        msg["To"] = receiver_email

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print("Registration email sent to", receiver_email)
    except Exception as e:
        print("Email Error:", e)

# DATABASE
def get_db_connection():
    conn=sqlite3.connect("database.db",check_same_thread=False)
    conn.row_factory=sqlite3.Row
    return conn

def create_table():
    conn=get_db_connection()

    conn.execute("""
    CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullname TEXT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT
    )""")

    conn.execute("""
    CREATE TABLE IF NOT EXISTS logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    log_type TEXT,
    level TEXT,
    source TEXT,
    event_id INTEGER,
    task TEXT,
    attack_type TEXT,
    severity TEXT,
    created_at TEXT
    ) """)
    conn.commit()
    conn.close()

# ALERT EMAIL FUNCTIOn
def send_alert_email(attack, severity, source, timestamp):
    try:
        subject = f"[Watchdog IDS] {severity} Alert Detected"
        body = f"""
        🚨 Watchdog IDS Security Alert 🚨

        Severity : {severity}
        Attack   : {attack}
        Source   : {source}
        Time     : {timestamp}
        Immediate investigation recommended.
        """
        send_email(subject, body)   
        print("Alert Email Sent")
    except Exception as e:
        print("Alert Email Failed:", e)

# LEVEL CONVERSION
def convert_level(level):
    mapping={
    1:"Error",
    2:"Warning",
    4:"Information"
    }
    return mapping.get(level,"Information")

# WINDOWS MONITOR
def monitor_windows_logs():
    if not WINDOWS_AVAILABLE:
        print("Windows monitoring disabled")
        return
    print("Live Windows Monitoring Started")
    seen=set()
    log_types=["System","Application","Security"]

    while True:
        for logtype in log_types:
            try:
                handle=win32evtlog.OpenEventLog(None,logtype)
                flags=win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events=win32evtlog.ReadEventLog(handle,flags,0)

                for event in events[:30]:
                    record=event.RecordNumber
                    if record in seen:
                        continue
                    seen.add(record)
                    event_id=event.EventID & 0xFFFF
                    level=convert_level(event.EventType)
                    source=event.SourceName
                    task=str(event.EventCategory)
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    # DETECTION
                    if logtype=="Security":
                        attack,severity=detect_attack({
                        "event_id":event_id,
                        "source":source,
                        "timestamp":datetime.now()
                        })
                    elif logtype=="System":
                        attack,severity=detect_system_event({
                        "event_id":event_id,
                        "level":level,
                        "source":source
                        })
                    elif logtype=="Application":
                        attack,severity=detect_application_event({
                        "event_id":event_id,
                        "level":level,
                        "source":source })
                    # INSERT DB

                    conn=get_db_connection()
                    conn.execute("""
                    INSERT INTO logs
                    (log_type,level,source,event_id,task,attack_type,severity,created_at)
                    VALUES (?,?,?,?,?,?,?,?)
                    """,
                    (
                    logtype,
                    level,
                    source,
                    event_id,
                    task,
                    attack,
                    severity,
                    timestamp  ))
                    conn.commit()
                    conn.close()
                    # SEND ALERT EMAIL (HIGH / CRITICAL)
                    if severity in ["HIGH", "CRITICAL"]:
                        conn_alert = get_db_connection()
                        users = conn_alert.execute("SELECT email FROM users").fetchall()
                        conn_alert.close()

                        for user in users:
                            subject = f"{severity} Security Alert - Watchdog IDS"
                            body = f"""
SECURITY ALERT

Severity : {severity}
Attack   : {attack}
Source   : {source}
Time     : {timestamp}

Immediate investigation recommended.
Watchdog IDS
"""
                            send_email(user["email"], subject, body)
            except Exception as e:
                print("Log Error:",e)
        time.sleep(5)
# REGISTER

@app.route("/register",methods=["GET","POST"])
def register():
    if request.method=="POST":
        fullname=request.form['fullname']
        username=request.form['username']
        email=request.form['email']
        password=request.form['password']
        hashed=bcrypt.hashpw(password.encode(),bcrypt.gensalt())
        conn=get_db_connection()

        try:
            conn.execute("""

            INSERT INTO users
            (fullname,username,email,password)
            VALUES(?,?,?,?)
            """,
            (fullname,username,email,hashed)

            )
            conn.commit()

            msg = "Registration Successful"
            # SEND REGISTRATION SUCCESS EMAIL
            subject = "Welcome to Watchdog IDS"
            body = f"""
            Hello {fullname},

Your registration with Watchdog IDS was successful.
You can now login and monitor system security events.

Login here:
http://localhost:5000/login

Thank you,
Watchdog IDS Team
"""
            send_email(email, subject, body)
        except:
            msg="User Exists"
        conn.close()

        return msg
    return render_template("register.html")
# LOGIN
@app.route("/login",methods=["GET","POST"])
def login():

    if request.method=="POST":
        username=request.form['username']
        password=request.form['password']
        conn=get_db_connection()
        user=conn.execute(
        "SELECT * FROM users WHERE username=?",
        (username,)
        ).fetchone()
        conn.close()

        if not user:
            return "User Not Found"
        if bcrypt.checkpw(password.encode(),user["password"]):
            session["user"]=username
            return redirect("/dashboard")
        return "Wrong Password"
    return render_template("login.html")

# DASHBOARD
@app.route("/dashboard")
def dashboard():

    if "user" not in session:
        return redirect("/login")
    conn=get_db_connection()

    # TOTAL LOGS
    total_logs=conn.execute(
    "SELECT COUNT(*) FROM logs"
    ).fetchone()[0]

    # ALERTS
    alert_logs=conn.execute("""
    SELECT COUNT(*)
    FROM logs
    WHERE severity IN ('MEDIUM','HIGH','CRITICAL')
    """).fetchone()[0]

    # HEALTH
    alert_percent=(alert_logs/total_logs)*100 if total_logs else 0
    health=int(max(0,100-alert_percent))

    # RECENT ALERTS
    recent_alerts=conn.execute("""
    SELECT *
    FROM logs
    WHERE severity IN ('MEDIUM','HIGH','CRITICAL')
    ORDER BY created_at DESC
    LIMIT 10
    """).fetchall()

    # LINE CHART DATA
    chart_data=conn.execute("""
    SELECT strftime('%H:%M', created_at) as time,
    COUNT(*) as total_logs,
    SUM(
    CASE
    WHEN severity IN ('MEDIUM','HIGH','CRITICAL')
    THEN 1
    ELSE 0
    END
    ) as threats
    FROM logs
    GROUP BY strftime('%H:%M', created_at)
    ORDER BY time DESC
    LIMIT 12
    """).fetchall()

    chart_data=chart_data[::-1]
    chart_times=[row["time"] for row in chart_data]
    chart_total=[row["total_logs"] for row in chart_data]
    chart_threats=[row["threats"] for row in chart_data]

    # PIE CHART DATA
    source_data=conn.execute("""
    SELECT source,COUNT(*) as count
    FROM logs
    GROUP BY source
    ORDER BY count DESC
    LIMIT 6
    """).fetchall()

    source_labels=[row["source"] for row in source_data]
    source_values=[row["count"] for row in source_data]
    # TOP ATTACK TYPES PIE
    attack_data=conn.execute("""
    SELECT attack_type,COUNT(*) as count
    FROM logs
    WHERE severity IN ('MEDIUM','HIGH','CRITICAL')
    GROUP BY attack_type
    ORDER BY count DESC
    LIMIT 6
    """).fetchall()

    attack_labels=[row["attack_type"] for row in attack_data]
    attack_values=[row["count"] for row in attack_data]
    conn.close()

    return render_template(
    "dashboard.html",
    total_logs=total_logs,
    alert_logs=alert_logs,
    health=health,
    recent_alerts=recent_alerts,

    chart_times=json.dumps(chart_times),
    chart_total=json.dumps(chart_total),
    chart_threats=json.dumps(chart_threats),

    source_labels=json.dumps(source_labels),
    source_values=json.dumps(source_values),

    attack_labels=json.dumps(attack_labels),
    attack_values=json.dumps(attack_values)
    )
# LIVE LOGS
@app.route("/live-logs")
def live_logs():
    log_type=request.args.get("type","System")
    conn=get_db_connection()
    logs=conn.execute("""
    SELECT *
    FROM logs
    WHERE log_type=?
    ORDER BY created_at DESC
    LIMIT 200
    """,(log_type.capitalize(),)).fetchall()

    system_count=conn.execute(
    "SELECT COUNT(*) FROM logs WHERE log_type='System'"
    ).fetchone()[0]

    app_count=conn.execute(
    "SELECT COUNT(*) FROM logs WHERE log_type='Application'"
    ).fetchone()[0]
    conn.close()

    return render_template(
    "live_logs.html",
    logs=logs,
    log_type=log_type.capitalize(),
    system_count=system_count,
    app_count=app_count
    )
# SECURITY ALERTS
@app.route("/alerts")
def alerts():

    if "user" not in session:
        return redirect("/login")
    conn=get_db_connection()
    logs=conn.execute("""
    SELECT *
    FROM logs
    WHERE log_type='Security'
    ORDER BY created_at DESC
    LIMIT 200

    """).fetchall()

    alert_count=conn.execute(
    "SELECT COUNT(*) FROM logs WHERE log_type='Security'"
    ).fetchone()[0]
    conn.close()

    return render_template(
        "alerts.html",
        logs=logs,
        alert_count=alert_count )
# LOGOUT
@app.route("/logout")
def logout():

    session.pop("user",None)

    return redirect("/login")

@app.route("/report")
def report():

    if "user" not in session:
        return redirect("/login")

    conn = get_db_connection()
    # Total logs
    total_logs = conn.execute(
        "SELECT COUNT(*) FROM logs"
    ).fetchone()[0]
    # Alerts
    alert_logs = conn.execute("""

        SELECT COUNT(*)
        FROM logs
        WHERE severity IN ('MEDIUM','HIGH','CRITICAL')

    """).fetchone()[0]
    # Health
    if total_logs == 0:
        health = 100
    else:
        health = int(100 - (alert_logs/total_logs)*100)
    # Threat summary
    threat_summary = conn.execute("""

        SELECT attack_type, COUNT(*)
        FROM logs
        WHERE severity IN ('MEDIUM','HIGH','CRITICAL')
        GROUP BY attack_type

    """).fetchall()
    # Severity summary
    severity_summary = conn.execute("""

        SELECT severity, COUNT(*)
        FROM logs
        GROUP BY severity

    """).fetchall()
    # Source summary
    source_summary = conn.execute("""

        SELECT source, COUNT(*)
        FROM logs
        GROUP BY source
        ORDER BY COUNT(*) DESC
        LIMIT 10

    """).fetchall()
    # Recent alerts
    alerts = conn.execute("""

        SELECT created_at, attack_type, severity
        FROM logs
        WHERE severity IN ('MEDIUM','HIGH','CRITICAL')
        ORDER BY created_at DESC
        LIMIT 10

    """).fetchall()
    conn.close()

    return render_template(
        "report.html",

        total_logs=total_logs,
        alert_logs=alert_logs,
        health=health,

        threat_summary=threat_summary,
        severity_summary=severity_summary,
        source_summary=source_summary,
        alerts=alerts,

        time=datetime.now()
    )
@app.route("/")
def home():
    return redirect("/login")

if __name__=="__main__":

    create_table()

    threading.Thread(
        target=monitor_windows_logs,
        daemon=True
    ).start()

    app.run(debug=True)