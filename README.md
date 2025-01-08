# 9-5-Ransomware-Time-Zone-Analysis-Script
A Python tool analyzing leak-site timestamps from Ransomware.live to find potential 9–5 schedules of ransomware groups. It stores data in SQLite, tests UTC offsets (–12 to +12), and computes a “9–5 Match Score” to suggest each group’s best-fitting time zone and likely countries.
