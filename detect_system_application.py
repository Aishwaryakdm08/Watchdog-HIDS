
from datetime import datetime

def normalize_event(event):
    """
    Ensures event dictionary always has safe values
    """

    return {

        "level": str(event.get("level","Information")),

        "event_id": int(event.get("event_id",0)),

        "source": str(event.get("source","Unknown")),

        "task": str(event.get("task","None")),

        "created_at": event.get(
            "created_at",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    }

# SYSTEM LOG DETECTION
def detect_system_event(event):

    event = normalize_event(event)

    event_id = event["event_id"]
    level = event["level"]
    source = event["source"].lower()

    # CRITICAL EVENTS
    if event_id == 41:
        return "KERNEL_POWER_FAILURE","HIGH"

    if event_id == 6008:
        return "UNEXPECTED_SHUTDOWN","HIGH"

    if event_id in [17,18]:
        return "HARDWARE_ERROR","HIGH"

    if event_id == 4616:
        return "TIME_MANIPULATION","HIGH"

    # SERVICE EVENTS
    if event_id in [7031,7034]:
        return "SERVICE_CRASH","MEDIUM"

    if event_id in [7040,7045]:
        return "SERVICE_CHANGE","MEDIUM"

    if "service control manager" in source:
        return "SERVICE_ACTIVITY","LOW"
    
    # DRIVER EVENTS
    if event_id == 219:
        return "DRIVER_FAILURE","MEDIUM"

    # NETWORK EVENTS
    if event_id in [4201,7021]:
        return "NETWORK_CHANGE","LOW"

    # POWER EVENTS
    if event_id == 56:
        return "POWER_EVENT","LOW"

    if event_id == 1074:
        return "SYSTEM_RESTART","LOW"

    if event_id == 6005:
        return "SYSTEM_BOOT","LOW"

    if event_id == 6006:
        return "SYSTEM_SHUTDOWN","LOW"

    # ERROR LEVEL
    if level.lower() == "error":
        return "SYSTEM_ERROR","MEDIUM"

    if level.lower() == "warning":
        return "SYSTEM_WARNING","MEDIUM"

    # DEFAULT
    return "NORMAL_SYSTEM","LOW"
# APPLICATION LOG DETECTION
def detect_application_event(event):
    event = normalize_event(event)
    event_id = event["event_id"]
    level = event["level"]
    source = event["source"].lower()

    # APPLICATION CRASH
    if event_id == 1000 and level.lower() == "error":
        return "APPLICATION_CRASH","HIGH"

    if event_id == 1001:
        return "APPLICATION_HANG","MEDIUM"

    # INSTALL / REMOVE
    if "msiinstaller" in source:

        if event_id in [1033,11707]:
            return "APPLICATION_INSTALL","MEDIUM"

        if event_id == 11724:
            return "APPLICATION_REMOVED","MEDIUM"

        return "APPLICATION_UPDATE","LOW"

    # SECURITY APPS
    if "defender" in source:
        return "SECURITY_ACTIVITY","HIGH"

    if "security" in source:
        return "SECURITY_ACTIVITY","HIGH"

    # DATABASE
    if "sql" in source:
        return "DATABASE_ACTIVITY","LOW"
    # WARNINGS
    if level.lower() == "warning":
        return "APPLICATION_WARNING","MEDIUM"
    # ERRORS
    if level.lower() == "error":
        return "APPLICATION_ERROR","MEDIUM"
    # NORMAL
    return "SOFTWARE_ACTIVITY","LOW"

# UNIVERSAL DETECTION
def detect_event(event, log_type):
    """
    Main detection function
    log_type = system | application
    """

    if log_type == "system":
        attack,severity = detect_system_event(event)
    elif log_type == "application":
        attack,severity = detect_application_event(event)
    else:
        attack,severity = "UNKNOWN","LOW"

    return {
        "level":event["level"],
        "created_at":event["created_at"],
        "source":event["source"],
        "event_id":event["event_id"],
        "task":event["task"],
        "attack_type":attack,
        "severity":severity
    } 