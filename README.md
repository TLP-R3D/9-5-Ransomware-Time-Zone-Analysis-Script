# 9-5-Ransomware-Time-Zone-Analysis-Script

A Python project to detect potential operating hours of ransomware groups by analyzing their leak-site post timestamps. It fetches data from Ransomware.live, stores it in a local SQLite database, and calculates a “9–5 Match Score” for each group—indicating how often they post within local 9 AM to 5 PM. By testing every UTC offset (–12 to +12), the script identifies the best-fitting time zone for each group, then lists likely countries/regions for that offset. Although this is a heuristic approach, it can offer strong clues when combined with other threat intelligence.

Features
Automated Data Fetch: Retrieves year-specific victim data from Ransomware.live/victims/<year>.
Local Database Storage: Uses SQLite to accumulate records over time, allowing historical trend analysis.
9–5 Heuristic: Shifts post timestamps through all time zones, measuring alignment with a typical workday schedule.
Per-Group Breakdown: Provides a “Best Offset” plus a top 5 list of possible countries for each ransomware group.
Extensible: Easy to add advanced analytics (day-of-week heatmaps, DST handling, additional threat intel) on top of the existing code.

Quick Start
Clone this repo.
Install dependencies: pip install -r requirements.txt (or individually for requests, pandas, matplotlib, seaborn).
Run: python3 9–5_Ransomware_Time-Zone_Analysis.py to fetch the data, analyze it, and print results in your terminal.

Why This Matters
Ransomware operators often behave like “office workers,” posting or leaking data during normal business hours in their local time. Pinpointing these hours helps narrow down their potential origins—while acknowledging this remains a best-effort approximation. Coupled with other threat intel (e.g., language usage, IP data, TTP patterns), this script can strengthen your analysis of ransomware group operations.
