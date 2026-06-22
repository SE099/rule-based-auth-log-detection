import re
from datetime import datetime


# Mapping of syslog month abbreviations to numeric month values.
#
# Authentication logs typically use abbreviated month names:
# Jan, Feb, Mar, ...
#
# These values are required to reconstruct a complete datetime object.
MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12
}


def parse_auth_log(line):
    """
    Parses a single Linux authentication log entry.

    The parser transforms raw SSH authentication log lines into
    structured event dictionaries. These dictionaries are later used
    by the rule engine to detect suspicious behavior.

    Parameters:
        line (str):
            A single raw line from auth.log.

    Returns:
        dict | None:
            A structured event dictionary if the line matches
            the expected SSH log format. Otherwise, None.
    """

    # Extract the general syslog structure.
    #
    # Example:
    # Jan 10 12:34:56 server sshd[1234]: Failed password for root from 192.168.1.10 port 22 ssh2
    pattern = (
        r"(?P<month>\w+) "
        r"(?P<day>\d+) "
        r"(?P<time>\d+:\d+:\d+) "
        r".* sshd.*: "
        r"(?P<message>.*)"
    )

    match = re.match(pattern, line)

    # Ignore log lines that are not SSH authentication events.
    if not match:
        return None

    data = match.groupdict()
    message = data["message"]

    # ------------------------------------------------------------------
    # Timestamp reconstruction
    # ------------------------------------------------------------------
    #
    # Syslog entries usually do not contain the year.
    #
    # Example:
    # Jan 10 12:34:56
    #
    # To support time-based detection rules, the parser reconstructs
    # a complete datetime object by combining:
    #
    # - month
    # - day
    # - time
    # - current year
    #
    # This allows the Rule Engine to evaluate events using their
    # actual occurrence time instead of the processing time.
    current_year = datetime.now().year

    timestamp = datetime(
        year=current_year,
        month=MONTHS[data["month"]],
        day=int(data["day"]),
        hour=int(data["time"].split(":")[0]),
        minute=int(data["time"].split(":")[1]),
        second=int(data["time"].split(":")[2])
    )

    # ------------------------------------------------------------------
    # Source IP extraction
    # ------------------------------------------------------------------
    #
    # Example:
    # Failed password for root from 192.168.1.10 port 22 ssh2
    #
    # Extracted IP:
    # 192.168.1.10
    ip_match = re.search(
        r"from (\d+\.\d+\.\d+\.\d+)",
        message
    )

    ip = ip_match.group(1) if ip_match else None

    # ------------------------------------------------------------------
    # Username extraction
    # ------------------------------------------------------------------
    #
    # Supported formats:
    #
    # Failed password for root ...
    # Failed password for invalid user admin ...
    #
    # The parser extracts only the actual username.
    user_match = re.search(
        r"for (invalid user )?(?P<user>[\w.-]+)",
        message
    )

    username = user_match.group("user") if user_match else None

    # ------------------------------------------------------------------
    # Event classification
    # ------------------------------------------------------------------
    #
    # The parser normalizes different SSH authentication messages into
    # a small set of standardized event categories.
    #
    # This simplifies rule implementation because the Rule Engine
    # no longer needs to interpret raw log messages.
    if "Failed password" in message:
        status = "failed"
        event_type = "ssh_failed_login"

    elif "Accepted password" in message:
        status = "success"
        event_type = "ssh_successful_login"

    else:
        status = "unknown"
        event_type = "ssh_other"

    # ------------------------------------------------------------------
    # Return normalized event object
    # ------------------------------------------------------------------
    #
    # The resulting event represents the internal data model of the
    # detection system.
    #
    # Both a datetime object and an ISO-formatted timestamp are stored:
    #
    # timestamp:
    #     Used internally for time-based calculations.
    #
    # timestamp_iso:
    #     Human-readable representation for logging, alerts,
    #     and debugging.
    return {
        "timestamp": timestamp,
        "timestamp_iso": timestamp.isoformat(),

        "month": data["month"],
        "day": data["day"],

        "message": message,

        "ip": ip,
        "username": username,

        "status": status,
        "event_type": event_type,

        "log_type": "auth"
    }
