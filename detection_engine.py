from collections import defaultdict
from datetime import datetime, timedelta

# MEMORY TRACKERS
failed_login_tracker = defaultdict(list)
login_success_tracker = defaultdict(list)
admin_login_tracker = defaultdict(list)

# THRESHOLDS
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = 60  # seconds

SUSPICIOUS_LOGIN_WINDOW = 60

# MAIN DETECTION FUNCTION
def detect_attack(event):
    """
    Professional IDS Detection Engine
    Input:
    {
        event_id
        timestamp
        source
    }
    Output:
    action, severity
    """
    event_id = event.get("event_id",0)
    timestamp = event.get("timestamp",datetime.now())
    source = event.get("source","Unknown")

    now = datetime.now()

    # CRITICAL INTRUSIONS
    # Security Log Cleared
    if event_id == 1102:
        return "LOG_TAMPERING","CRITICAL"

    # Admin privileges assigned
    if event_id == 4672:
        return "PRIVILEGE_ESCALATION","HIGH"

    # Account lockout
    if event_id == 4740:
        return "ACCOUNT_LOCKOUT","HIGH"

    # FAILED LOGIN DETECTION
    if event_id == 4625:
        failed_login_tracker[source].append(now)

        # Remove old entries
        failed_login_tracker[source] = [
            t for t in failed_login_tracker[source]
            if now - t < timedelta(seconds=BRUTE_FORCE_WINDOW)
        ]
        if len(failed_login_tracker[source]) >= BRUTE_FORCE_THRESHOLD:
            return "BRUTE_FORCE_ATTACK","CRITICAL"

        return "FAILED_LOGIN","MEDIUM"

    # SUCCESS LOGIN
    if event_id == 4624:
        login_success_tracker[source].append(now)

        if source in failed_login_tracker:
            recent_failures = [
                t for t in failed_login_tracker[source]
                if now - t < timedelta(seconds=SUSPICIOUS_LOGIN_WINDOW)
            ]

            if len(recent_failures) >= 3:
                return "SUSPICIOUS_LOGIN","HIGH"

        return "LOGIN_SUCCESS","LOW"

    # PASSWORD CHANGE
    if event_id == 4723 or event_id == 4724:
        return "PASSWORD_CHANGE","MEDIUM"

    # USER ACCOUNT EVENTS
    if event_id == 4720:
        return "USER_CREATED","MEDIUM"

    if event_id == 4726:
        return "USER_DELETED","MEDIUM"

    # POLICY CHANGES
    if event_id == 4719:
        return "SECURITY_POLICY_CHANGE","HIGH"

    # NORMAL SECURITY ACTIVITY
    return "NORMAL_ACTIVITY","LOW"