# 🔵 Splunk Log Analysis – Brute Force Detection Lab

## 📌 Overview
In this lab, I used Splunk to analyse web server logs and identify suspicious activity. The goal was to detect potential attacks such as brute force login attempts and unauthorised access to sensitive endpoints.

---

## 🧠 What is Splunk?
Splunk is a **SIEM tool** that helps security teams collect, search, and analyse logs from systems and applications.

In simple terms, Splunk helps analysts:
- collect log data
- search through activity
- detect suspicious behaviour
- investigate possible attacks

---

## ⚙️ Lab Setup
- Installed Splunk Enterprise locally
- Uploaded sample Apache web server logs
- Used Splunk Search & Reporting to analyse the data

---

## 🔍 Step 1 – View All Logs

```spl
index=main
```

### What this does
Displays all ingested log data.

### Key Finding
- Multiple IP addresses were interacting with the web server
- Requests were made to endpoints such as `/login`, `/admin`, and `/robots.txt`

---

## 🔍 Step 2 – Identify Most Active IP

```spl
index=main | rex field=_raw "^(?<ip>\d+\.\d+\.\d+\.\d+)" | stats count by ip | sort -count
```

### What this does
- Extracts IP addresses from the raw logs
- Counts how many requests each IP made
- Sorts the results from highest to lowest

### Key Finding

| IP Address | Requests |
|-----------|----------|
| 10.0.0.5 | 10 |
| 192.168.1.10 | 2 |
| 203.0.113.5 | 2 |
| 66.249.66.1 | 2 |

This showed that **10.0.0.5** was the most active IP address and stood out as suspicious.

---

## 🔍 Step 3 – Detect Failed Logins

```spl
index=main 401
```

### What this does
Filters the logs to show failed login attempts or failed requests with a `401` response code.

### Key Finding
- There were 9 failed login attempts
- These were linked to repeated `POST /login` requests
- The activity came from the IP address **10.0.0.5**

This suggested repeated login attempts against the login page.

---

## 🔍 Step 4 – Count Failed Logins by IP

```spl
index=main 401 | rex field=_raw "^(?<ip>\d+\.\d+\.\d+\.\d+)" | stats count by ip | sort -count
```

### What this does
- Filters for failed login events only
- Extracts the IP address from each event
- Counts how many failed logins came from each IP

### Key Finding

| IP Address | Failed Logins |
|-----------|---------------|
| 10.0.0.5 | 9 |

This confirmed that all failed login attempts were coming from the same IP address.

---

## 🔍 Step 5 – Detect Access to Admin Page

```spl
index=main "/admin"
```

### What this does
Searches for requests made to the `/admin` page.

### Key Finding
- The IP address **203.0.113.5** attempted to access `/admin`
- The server responded with **403 Forbidden**

This suggested an unauthorised attempt to access a restricted page.

---

## 🚨 Findings and Analysis

### Suspicious IP Activity
The IP address **10.0.0.5** made 10 total requests, which was far more than the other IP addresses in the dataset. This made it stand out as the most suspicious source of traffic.

### Brute Force Behaviour
The same IP address, **10.0.0.5**, generated 9 failed login attempts using `POST /login` requests with a `401` response code. This pattern strongly suggests a brute force login attempt.

### Possible Account Compromise
After multiple failed attempts, the same IP address later received a `200` response on a login request. This could indicate the attacker eventually guessed the correct credentials and successfully logged in.

### Unauthorised Admin Access Attempt
A separate IP address, **203.0.113.5**, attempted to access the `/admin` endpoint and received a `403 Forbidden` response. This suggests probing or reconnaissance activity against a protected admin page.

---

## ✅ Conclusion
In this lab, I used Splunk to ingest and analyse web server logs. By running targeted searches, I was able to identify suspicious behaviour, including repeated failed login attempts, a likely brute force attack, and an attempt to access a restricted admin page.

The main conclusions from this investigation were:
- **10.0.0.5** was the most suspicious IP address
- It generated repeated failed login attempts against `/login`
- A later successful login response suggested possible account compromise
- **203.0.113.5** attempted to access `/admin` and was denied

---

## 🛠 Skills Demonstrated
- Splunk installation and setup
- Log ingestion into Splunk
- Searching and filtering log data
- Regex field extraction using `rex`
- Identifying suspicious IP activity
- Detecting brute force login behaviour
- Investigating access to sensitive endpoints
- Drawing conclusions from log evidence

---

## 📚 Simple Summary
This lab showed how Splunk can be used to investigate suspicious web activity. I uploaded log files, searched through the events, identified the busiest IP address, filtered failed logins, and found signs of a brute force attack. I also detected a separate attempt to access a restricted admin page.

---

## 🚀 Next Steps
- Analyse larger and more realistic log datasets
- Create Splunk dashboards to visualise suspicious activity
- Build alerts for repeated failed logins
- Simulate attacks from a VM and detect them in Splunk
