import requests
import statistics
import sqlite3
import os
from datetime import datetime
import pandas as pd

# -----------------------------------------------------------------
# CONFIG
# -----------------------------------------------------------------
API_URL = "https://api.ransomware.live/victims/2025"  # Example for 2024 data
HEADERS = {"accept": "application/json"}
DB_NAME = "ransomware_data.db"  # SQLite database file

# The "9–5 window" for local business hours
START_HOUR = 9
END_HOUR = 17

# A complete dictionary of UTC offsets (–12..+12) → possible regions.
OFFSET_COUNTRIES = {
    -12: ["Baker Island (US)", "Howland Island (US)"],
    -11: ["American Samoa", "Niue (NZ)"],
    -10: ["Hawaii (US)", "Cook Islands (NZ)"],
    -9:  ["Alaska (US)"],
    -8:  ["US Pacific (California, Washington)", "Canada (Pacific)"],
    -7:  ["US Mountain", "Canada (Mountain)"],
    -6:  ["US Central", "Mexico (Central)", "Guatemala", "Costa Rica"],
    -5:  ["US Eastern", "Canada (Eastern)", "Colombia", "Peru"],
    -4:  ["Atlantic (Canada)", "Bolivia", "Venezuela"],
    -3:  ["Argentina", "Brazil (East)", "Chile"],
    -2:  ["Fernando de Noronha (Brazil)"],
    -1:  ["Azores (Portugal)"],
     0:  ["UK", "Ireland", "Portugal (mainland)", "Iceland", "Morocco"],
     1:  ["Central Europe (Germany, France)", "Algeria", "Nigeria"],
     2:  ["Eastern Europe (Ukraine, Greece)", "Israel", "Egypt", "South Africa", "Romania"],
     3:  ["Russia (Moscow)", "Saudi Arabia", "Kenya"],
     4:  ["United Arab Emirates", "Armenia", "Seychelles"],
     5:  ["Pakistan", "Uzbekistan", "Maldives"],
     6:  ["Bangladesh", "Bhutan"],
     7:  ["Thailand", "Vietnam", "Cambodia"],
     8:  ["China", "Singapore", "Malaysia", "Western Australia"],
     9:  ["Japan", "South Korea", "East Timor"],
    10:  ["Eastern Australia", "Papua New Guinea", "Guam"],
    11:  ["Solomon Islands", "New Caledonia (France)"],
    12:  ["Fiji", "New Zealand", "Tuvalu", "Marshall Islands"]
}

# Example holiday/festive dates (partial, simplified). 
# Real 2024 approximations for demonstration:
HOLIDAYS = {
    "US Eastern": [
        ("2024-11-28", "2024-11-28"),  # Thanksgiving (1 day)
        ("2024-12-24", "2024-12-25"),  # Christmas Eve & Day
    ],
    "Israel": [
        ("2024-04-23", "2024-05-01"),  # Passover (Pesach) approx.
    ],
    "Egypt": [
        ("2024-03-11", "2024-04-09"),  # Ramadan approx
        ("2024-04-10", "2024-04-10"),  # Eid al-Fitr
    ],
    "UK": [
        ("2024-03-31", "2024-03-31"),  # Easter Sunday
        ("2024-12-25", "2024-12-25"),  # Christmas
    ],
    # Etc. for other regions if desired
}

# For a simple religious pattern guess (Sunday vs Friday)
JUDEO_CHRISTIAN_NON_WORK_DAYS = {6}  # Sunday is index 6
ISLAMIC_NON_WORK_DAYS = {4}         # Friday is index 4


def create_db_and_table():
    """Initialize SQLite database for storing victim posts."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS victims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_name TEXT NOT NULL,
            discovered TEXT NOT NULL,
            UNIQUE(group_name, discovered)
        )
    """)
    conn.commit()
    conn.close()


def fetch_data_from_api():
    """Fetch data from the specified Ransomware.live endpoint."""
    try:
        resp = requests.get(API_URL, headers=HEADERS)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as e:
        print(f"Error fetching data: {e}")
        return []

    valid_records = []
    for item in data:
        discovered = item.get("discovered")
        group_name = item.get("group_name")
        if discovered and group_name:
            valid_records.append({"group_name": group_name, "discovered": discovered})
    return valid_records


def store_records_in_db(records):
    """Insert new records into the DB; duplicates are ignored."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    for r in records:
        try:
            cursor.execute(
                "INSERT OR IGNORE INTO victims (group_name, discovered) VALUES (?, ?)",
                (r["group_name"], r["discovered"])
            )
        except sqlite3.Error as e:
            print(f"DB insert error: {e}")
    conn.commit()
    conn.close()


def gather_all_data():
    """Retrieve all stored data from the DB."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT group_name, discovered FROM victims")
    rows = cursor.fetchall()
    conn.close()

    data = []
    for group_name, discovered in rows:
        data.append({"group_name": group_name, "discovered": discovered})
    return data


def parse_timestamp(discovered_str):
    """
    Convert the discovered time string into:
      (dt (datetime), hour_in_utc, weekday)
    weekday: 0=Monday, ..., 6=Sunday
    Accepts formats with or without microseconds.
    """
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(discovered_str, fmt)
            return dt, dt.hour, dt.weekday()
        except ValueError:
            pass
    return None, None, None


def in_holiday_period(dt, region):
    """
    Checks if the datetime `dt` falls within a known holiday range for the given region.
    Only compares the date portion (yyyy-mm-dd).
    """
    if region not in HOLIDAYS:
        return False

    for start_str, end_str in HOLIDAYS[region]:
        try:
            start_dt = datetime.strptime(start_str, "%Y-%m-%d")
            end_dt = datetime.strptime(end_str, "%Y-%m-%d")
            if start_dt.date() <= dt.date() <= end_dt.date():
                return True
        except ValueError:
            continue
    return False


def build_distribution(df):
    """
    Build a distribution for each group with:
      - hour_counts: [count for UTC hour 0..23]
      - weekday_counts: [count for Monday..Sunday]
      - total_posts
    """
    dist_data = {}
    for _, row in df.iterrows():
        group = row["group_name"]
        dt_obj = row["dt_obj"]      # the datetime
        hour_utc = row["HourUTC"]
        wday = row["Weekday"]

        if group not in dist_data:
            dist_data[group] = {
                "hour_counts": [0]*24,
                "weekday_counts": [0]*7,
                "total_posts": 0
            }

        if hour_utc is not None:
            dist_data[group]["hour_counts"][hour_utc] += 1
        if wday is not None:
            dist_data[group]["weekday_counts"][wday] += 1

        dist_data[group]["total_posts"] += 1

    return dist_data


def measure_fit_to_offset(hour_counts, offset):
    """
    For a group's 24-hour distribution, measure how many posts fall in local 9–5
    with local_hour = (utc_hour + offset) % 24.
    Returns fraction of total posts in that local 9-17 window.
    """
    total_posts = sum(hour_counts)
    if total_posts == 0:
        return 0.0

    business_posts = 0
    for utc_hour, count in enumerate(hour_counts):
        local_hour = (utc_hour + offset) % 24
        if START_HOUR <= local_hour < END_HOUR:
            business_posts += count

    return business_posts / total_posts


def find_best_offset(dist_data):
    """
    For each group, test every offset from -12..+12
    and pick the one that yields the highest fraction of 9–5 local posts.
    """
    results = []
    for group, info in dist_data.items():
        hour_counts = info["hour_counts"]
        best_offset = None
        best_score = -1.0

        for offset in OFFSET_COUNTRIES.keys():
            score = measure_fit_to_offset(hour_counts, offset)
            if score > best_score:
                best_score = score
                best_offset = offset

        results.append({
            "group": group,
            "best_offset": best_offset,
            "best_score": best_score,
            "weekday_counts": info["weekday_counts"],
            "total_posts": info["total_posts"],
            "hour_counts": info["hour_counts"]
        })

    return results


def guess_cultural_pattern(weekday_counts):
    """
    Simple approach to see if the group avoids Sunday or Friday:
      - Sunday = day 6
      - Friday = day 4
    Compare usage of that day to average usage. If significantly less, guess a pattern.
    """
    total = sum(weekday_counts)
    if total == 0:
        return "No data"

    avg_per_day = total / 7
    ratio_sunday = weekday_counts[6] / avg_per_day if avg_per_day else 0
    ratio_friday = weekday_counts[4] / avg_per_day if avg_per_day else 0

    patterns = []
    if ratio_sunday < 0.5:
        patterns.append("Possible Judeo-Christian (low Sunday usage)")
    if ratio_friday < 0.5:
        patterns.append("Possible Islamic (low Friday usage)")

    if not patterns:
        return "No strong religious pattern detected"
    return " | ".join(patterns)


def main():
    # 1. DB Setup
    create_db_and_table()

    # 2. Fetch data
    print("Fetching victim data from the API...")
    new_recs = fetch_data_from_api()
    print(f"Retrieved {len(new_recs)} records from the API.")

    # 3. Store records
    store_records_in_db(new_recs)

    # 4. Gather all data
    all_data = gather_all_data()
    print(f"Total records in DB: {len(all_data)}")

    if not all_data:
        print("No data to analyze.")
        return

    # 5. Convert to DataFrame
    df_all = pd.DataFrame(all_data)
    df_all["dt_obj"], df_all["HourUTC"], df_all["Weekday"] = zip(*df_all["discovered"].apply(parse_timestamp))
    df_all.dropna(subset=["HourUTC"], inplace=True)

    # 6. Build distribution
    dist_data = build_distribution(df_all)

    # 7. Identify best offsets
    results = find_best_offset(dist_data)

    # 8. Print results
    print("\n--- 9–5 + Holiday/Festive Analysis (Improved with Full Offsets) ---\n")
    for r in results:
        group = r["group"]
        offset = r["best_offset"]
        score = r["best_score"]
        total = r["total_posts"]
        wdays = r["weekday_counts"]

        # Attempt to guess cultural pattern
        pattern_guess = guess_cultural_pattern(wdays)

        # Retrieve plausible countries from the full dictionary
        top_countries = OFFSET_COUNTRIES.get(offset, ["Unknown offset"])[:3]

        print(f"Group: {group}")
        print(f"  Best Offset: UTC{offset:+d}  (9–5 Match Score: {score:.2f})")
        print(f"  Total Posts: {total}")
        print(f"  Likely Regions: {top_countries}")
        print(f"  Religious Pattern Guess: {pattern_guess}")
        print()

    print("Note: For holiday checks, you'd run a second pass after determining region,")
    print("using in_holiday_period(dt, region) on each post for that region.\n")


if __name__ == "__main__":
    main()
