# Rule-Based Authentication Log Detection System

## Overview

This repository contains the implementation of a lightweight rule-based intrusion detection system developed as part of a Bachelor's thesis in the field of Information Security.

The system analyzes Linux authentication logs and detects security-relevant events by applying predefined detection rules to structured log data. The primary objective is to demonstrate how rule-based detection mechanisms can be used to identify common authentication-related attack patterns while maintaining transparency, interpretability, and low computational complexity.

The implementation follows a modular architecture consisting of:

* Log Parser
* Event Normalization Component
* Rule Engine
* Alert Generation Module

The system was developed as a proof-of-concept prototype and is intended for educational and research purposes.

---

## Implemented Detection Rules

The current version implements four detection mechanisms:

### 1. Brute-Force Attack Detection

Detects multiple failed login attempts originating from the same IP address.

**Trigger condition:**

* 5 failed login attempts
* within 60 seconds
* from the same source IP

---

### 2. Repeated Failed Authentication Detection

Detects repeated authentication failures targeting the same user account.

**Trigger condition:**

* 3 failed login attempts
* within 120 seconds
* for the same username

---

### 3. Suspicious Login Behavior Detection

Detects successful login attempts occurring outside the expected login time range.

**Trigger condition:**

* Successful login
* Outside 06:00–22:00

---

### 4. IP-Based Login Analysis

Detects authentication attempts against multiple user accounts from the same source IP address.

**Trigger condition:**

* Authentication attempts for at least 3 different usernames
* within 120 seconds
* from the same source IP

---

## Project Structure

```text
detection-system/
│
├── main.py
│
├── parsers/
│   └── auth_parser.py
│
├── engine/
│   └── rule_engine.py
│
├── logs/
│   ├── auth.log
│   ├── test1_bruteforce.log
│   ├── test2_repeated_failed_auth.log
│   ├── test3_suspicious_login.log
│   ├── test4_ip_analysis.log
│   └── test5_legitimate_authentication_activity.log
│
└── README.md
```

---

## Prerequisites

The project was developed and tested using:

* Python 3.11+
* Windows 11
* PyCharm Community Edition

No external Python packages are required.

Only standard Python libraries are used:

* datetime
* re
* collections
* sys

---

## Installation

Clone the repository:

```bash
git clone <repository-url>
cd detection-system
```

Verify the Python installation:

```bash
python --version
```

Expected output:

```text
Python 3.x.x
```

---

## Running the Detection System

The system accepts a log file as a command-line argument.

General syntax:

```bash
python main.py <logfile>
```

Example:

```bash
python main.py logs/auth.log
```

---

## Evaluation Scenarios

The repository contains five predefined test scenarios used during the evaluation presented in the Bachelor's thesis.

### Test 1 – Brute-Force Attack

```bash
python main.py logs/test1_bruteforce.log
```

Expected result:

* Brute-Force Detection Alert
* Repeated Failed Authentication Alert

---

### Test 2 – Repeated Failed Authentication

```bash
python main.py logs/test2_repeated_failed_auth.log
```

Expected result:

* Repeated Failed Authentication Alert

---

### Test 3 – Suspicious Login Behavior

```bash
python main.py logs/test3_suspicious_login.log
```

Expected result:

* Suspicious Login Alert

---

### Test 4 – IP-Based Login Analysis

```bash
python main.py logs/test4_ip_analysis.log
```

Expected result:

* IP-Based Login Analysis Alert

---

### Test 5 – Legitimate Authentication Activity

```bash
python main.py logs/test5_legitimate_authentication_activity.log
```

Expected result:

* No alerts generated

---

## Example Detection Output

```text
[ALERT] Brute-force attack detection |
Time: 2026-01-10T12:00:40 |
User: root |
IP: 192.168.1.10 |
Event: ssh_failed_login |
Description: 5 failed login attempts from the same IP within 60 seconds
```

Each alert contains:

* Timestamp
* Username
* Source IP address
* Event type
* Triggered detection rule
* Alert description

---

## Detection Workflow

The detection process follows the workflow below:

```text
Authentication Log
        ↓
Log Parser
        ↓
Structured Event Object
        ↓
Rule Engine
        ↓
Rule Evaluation
        ↓
Alert Generation
```

---

## Limitations

The current prototype intentionally focuses on a limited scope.

Current limitations include:

* Support for Linux authentication logs only
* Static rule thresholds
* No correlation across multiple log sources
* No machine learning capabilities
* Evaluation based on controlled test scenarios

---

## Future Work

Possible future extensions include:

* Additional log sources
* YAML-based rule definitions
* Event correlation engine
* Threat intelligence integration
* Machine learning assisted detection
* Real-time log monitoring

---

## Academic Context

This repository accompanies the Bachelor's thesis:

**"Rule-Based Detection of Security-Relevant Events in Authentication Log Data"**

The implementation serves as a proof-of-concept prototype demonstrating how authentication logs can be processed, analyzed, and evaluated using transparent rule-based detection mechanisms.

---

## License

This project is provided for academic and educational purposes.
