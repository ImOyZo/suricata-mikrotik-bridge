#!/usr/bin/env python3

import os
import json
import requests
import pyinotify
from time import sleep

# Configuration Settings
ENABLE_TELEGRAM = True
TELEGRAM_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHATID = "YOUR_CHAT_ID"

FILEPATH = os.path.abspath("/var/log/suricata/eve.json")

NOTIFY_ON_SEVERITY = [1, 2, 3]

last_pos = 0

def send_telegram_notification(alert_data):
    """
    Formats the alert data and sends it via Telegram.
    """
    if not ENABLE_TELEGRAM:
        return

    try:
        # Extract relevant data
        timestamp = alert_data.get("timestamp", "N/A")
        src_ip = alert_data.get("src_ip", "N/A")
        dest_ip = alert_data.get("dest_ip", "N/A")
        dest_port = alert_data.get("dest_port", "N/A")
        proto = alert_data.get("proto", "N/A")
        
        alert_info = alert_data.get("alert", {})
        signature = alert_info.get("signature", "Unknown Signature")
        severity = alert_info.get("severity", "N/A")
        category = alert_info.get("category", "N/A")

        # Create a formatted message (HTML)
        message = (
            f"<b>Suricata Alert Detected</b>\n\n"
            f"<b>Signature:</b> {signature}\n"
            f"<b>Severity:</b> {severity}\n"
            f"<b>Category:</b> {category}\n\n"
            f"<b>Source:</b> {src_ip}\n"
            f"<b>Destination:</b> {dest_ip}:{dest_port} ({proto})\n"
            f"<b>Time:</b> {timestamp}"
        )

        telegram_url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        params = {
            "chat_id": TELEGRAM_CHATID,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": "true"
        }
        
        response = requests.get(telegram_url, params=params, timeout=10)
        
        if response.status_code == 200:
            print(f"[Monitor] Notification sent for {signature}")
        else:
            print(f"[Monitor] Failed to send Telegram: {response.text}")

    except Exception as e:
        print(f"[Monitor] Error sending Telegram: {e}")

def process_new_lines(lines):
    """
    Parses new lines from the log file and triggers notifications.
    """
    for line in lines:
        try:
            if not line.strip():
                continue

            entry = json.loads(line)

            # Check if it is an Alert event
            if entry.get("event_type") != "alert":
                continue

            # Check Severity Level
            severity = entry.get("alert", {}).get("severity")
            
            # Ensure severity is an integer for comparison
            try:
                severity = int(severity)
            except (ValueError, TypeError):
                continue

            if severity in NOTIFY_ON_SEVERITY:
                send_telegram_notification(entry)

        except json.JSONDecodeError:
            continue # Skip malformed lines
        except Exception as e:
            print(f"[Monitor] Error processing line: {e}")

def read_file_changes(fpath):
    global last_pos
    lines = []
    
    try:
        if os.path.exists(fpath):
            with open(fpath, 'r') as f:
                f.seek(last_pos)
                lines = f.readlines()
                last_pos = f.tell()
    except Exception as e:
        print(f"[Monitor] Error reading file: {e}")
        
    return lines

class EventHandler(pyinotify.ProcessEvent):
    def process_IN_MODIFY(self, event):
        if event.pathname == FILEPATH:
            new_lines = read_file_changes(FILEPATH)
            if new_lines:
                process_new_lines(new_lines)

    def process_IN_CREATE(self, event):
        # Handle log rotation
        if event.pathname == FILEPATH:
            print(f"[Monitor] New eve.json detected. Resetting position.")
            global last_pos
            last_pos = 0
            # Read from beginning of new file
            new_lines = read_file_changes(FILEPATH)
            process_new_lines(new_lines)

def seek_to_end(fpath):
    """
    Jumps to the end of the file on startup to avoid processing old logs.
    """
    global last_pos
    if os.path.exists(fpath):
        last_pos = os.path.getsize(fpath)
        print(f"[Monitor] Jumped to end of file (Size: {last_pos} bytes)")
    else:
        print(f"[Monitor] File {fpath} not found yet. Waiting...")
        last_pos = 0

def main():
    print("--- Suricata Monitor Started ---")
    print(f"Monitoring: {FILEPATH}")
    print(f"Alerting on Severities: {NOTIFY_ON_SEVERITY}")

    # Set initial position
    seek_to_end(FILEPATH)

    # Setup Pyinotify
    wm = pyinotify.WatchManager()
    handler = EventHandler()
    notifier = pyinotify.Notifier(wm, handler)

    directory_to_monitor = os.path.dirname(FILEPATH)
    
    # Ensure directory exists
    if not os.path.exists(directory_to_monitor):
        print(f"Error: Directory {directory_to_monitor} does not exist.")
        return

    # Add watch
    wm.add_watch(directory_to_monitor, pyinotify.IN_CREATE | pyinotify.IN_MODIFY, rec=False)

    try:
        notifier.loop()
    except KeyboardInterrupt:
        print("\n[Monitor] Stopping...")
    except Exception as e:
        print(f"[Monitor] Unexpected error: {e}")

if __name__ == "__main__":
    main()