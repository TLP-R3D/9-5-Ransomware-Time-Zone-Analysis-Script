import requests
import statistics
import sqlite3
import os
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# -----------------------------------------------------------------
# CONFIG
# -----------------------------------------------------------------
API_URL = "https://api.ransomware.live/victims/2024"
HEADERS = {"accept": "application/json"}
DB_NAME = "ransomware_data.db"  # SQLite database file

# Potential UTC offsets to consider (from -12 to +12)
POSSIBLE_OFFSETS = list(range(-12, 13))

# The "9–5 window" for local business hours
START_HOUR = 9
END_HOUR = 17

# Dictionary of offsets → a list of possible countries/regions
# We’ll just store some examples for demonstration purposes.
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
    """
    Fetch the 100 most recent victims from the Ransomware.live API.
    Returns a list of dicts with 'group_name' and 'discovered'.
    """
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
    """Insert new records into the DB; duplicates are ignored via 'INSERT OR IGNORE'."""
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
    """Retrieve all stored data from the DB as a list of dicts."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT group_name, discovered FROM victims")
    rows = cursor.fetchall()
    conn.close()

    data = []
    for group_name, discovered in rows:
        data.append({"group_name": group_name, "discovered": discovered})
    return data

def parse_utc_hour(discovered_str):
    """
    Convert the discovered time string into:
      (hour_in_utc, weekday_index)
    weekday_index: 0=Monday, 6=Sunday
    Accepts formats with or without microseconds.
    """
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(discovered_str, fmt)
            return dt.hour, dt.weekday()
        except ValueError:
            pass
    # If neither format worked
    return None, None

def build_distribution(df):
    """
    Build a 24-bin histogram for each group to count how many posts happened at each UTC hour.
    Also track how many posts happen on weekdays vs. weekends.
    Returns a dict keyed by group_name, storing 'hour_counts', 'weekday_posts', 'weekend_posts', 'total_posts'.
    """
    dist_data = {}
    for _, row in df.iterrows():
        group = row["group_name"]
        hour = row["HourUTC"]
        wday = row["Weekday"]

        if group not in dist_data:
            dist_data[group] = {
                "hour_counts": [0]*24,
                "weekday_posts": 0,
                "weekend_posts": 0,
                "total_posts": 0
            }
        dist_data[group]["hour_counts"][int(hour)] += 1

        if wday < 5:
            dist_data[group]["weekday_posts"] += 1
        else:
            dist_data[group]["weekend_posts"] += 1

        dist_data[group]["total_posts"] += 1
    return dist_data

def measure_fit_to_offset(hour_counts, offset):
    """
    For a given group's 24-hour distribution (hour_counts),
    figure out how many posts land in 'local' 9–5 when offset from UTC.
      local_hour = (utc_hour + offset) % 24
    Returns a float score = fraction of total posts falling in 9–17 local time.
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
    For each group, test every offset from -12 to +12, pick the one
    that yields the highest fraction of posts in the '9-5 local' window.
    """
    results = []
    for group, info in dist_data.items():
        hour_counts = info["hour_counts"]
        best_offset = None
        best_score = -1.0

        for offset in POSSIBLE_OFFSETS:
            score = measure_fit_to_offset(hour_counts, offset)
            if score > best_score:
                best_score = score
                best_offset = offset

        results.append({
            "group": group,
            "best_offset": best_offset,
            "best_score": best_score,
            "weekday_posts": info["weekday_posts"],
            "weekend_posts": info["weekend_posts"],
            "total_posts": info["total_posts"],
            "hour_counts": hour_counts
        })

    return results

def get_top_countries_for_offset(offset, top_n=5):
    """
    Given a best offset, return up to 'top_n' possible countries/regions
    from the OFFSET_COUNTRIES dictionary.
    """
    if offset in OFFSET_COUNTRIES:
        return OFFSET_COUNTRIES[offset][:top_n]
    return ["Unknown offset"]

def main():
    # 1. Initialize DB
    create_db_and_table()

    # 2. Fetch new data
    print("Fetching recent victims from the Ransomware.live API...")
    new_recs = fetch_data_from_api()
    print(f"Retrieved {len(new_recs)} new records from the API.")

    # 3. Insert into DB
    store_records_in_db(new_recs)

    # 4. Gather all data
    all_data = gather_all_data()
    print(f"Total records in DB: {len(all_data)}")

    if not all_data:
        print("No data to analyze—exiting.")
        return

    # 5. Convert to DataFrame
    df_all = pd.DataFrame(all_data)

    # Parse the discovered times into (hour_utc, weekday)
    df_all["HourUTC"], df_all["Weekday"] = zip(*df_all["discovered"].apply(parse_utc_hour))

    # Drop rows where we couldn't parse hour
    df_all.dropna(subset=["HourUTC"], inplace=True)

    # 6. Build hour distributions for each group
    dist_data = build_distribution(df_all)

    # 7. Identify best offset/time zone
    results = find_best_offset(dist_data)

    # 8. Print final results
    print("\n--- Analysis Results ---\n")
    for r in results:
        group = r["group"]
        offset = r["best_offset"]
        score = r["best_score"]
        wdays = r["weekday_posts"]
        wends = r["weekend_posts"]
        total = r["total_posts"]

        top_countries = get_top_countries_for_offset(offset)

        print(f"Group: {group}")
        print(f"  Best Offset: UTC{offset:+d}")
        print(f"  9–5 Match Score: {score:.2f} (≈ {score*100:.1f}% in local 9–5)")
        print(f"  Weekdays: {wdays}, Weekends: {wends}, TotalPosts: {total}")
        print("  Top 5 Likely Locations (based on offset):")
        for place in top_countries:
            print(f"    - {place}")
        print()

    # (Optional) If you want advanced charts, day-of-week heatmaps, or more, you can implement them here.
    # e.g., show a distribution chart for each group, etc.


if __name__ == "__main__":
    main()
