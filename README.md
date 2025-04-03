Teacher-Parent Meeting Scheduler 🏫👨‍👩‍👧‍👦

A Flask-based system for fair teacher-parent meeting assignments with real-time updates.

Features ✨
- **Fair Teacher Assignment**: Round-robin scheduling ensures parents meet all teachers.
- **Real-Time Updates**: SSE (Server-Sent Events) for live meeting notifications.
- **Priority Queue**: First-come-first-served when all teachers are busy.
- **Workload Balancing**: Least-busy teacher gets new assignments.
- **RFID Integration**: Scan cards to trigger meetings.

How It Works ⚙️
Token Assignment Algorithm:
1. Parents scan RFID cards with unique tokens.
2. System assigns them to:
   - The next teacher they haven’t met, or
   - The least-busy teacher if all are occupied.
3. Teachers mark meetings complete → Next parent in queue gets assigned.

Parent A → Teacher 1 → Teacher 2 → Teacher 3 (Cycle repeats)
Parent B → Teacher 2 → Teacher 3 → Teacher 1

**********************************************************************************
Installation 🛠️
Clone the repo: 
git clone https://github.com/yourusername/teacher-parent-scheduler.git
cd teacher-parent-scheduler


Set up Python environment:
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install -r requirements.txt


Initialize the database:
python init_db.py


Run the server:
flask run --host=0.0.0.0

**********************************************************************************
API Endpoints 🌐
Endpoint	Method	Description
/api	GET	Assign teacher to parent (RFID scan)
/updates	GET	SSE stream for real-time meeting alerts
/api/complete_meeting	POST	Mark meeting as complete
**********************************************************************************
Testing 🧪
1.Simulate an RFID scan:
curl "http://localhost:5000/api?cardUID=PARENT_123&token=456"


2.Complete a meeting (replace YOUR_TOKEN):
curl -X POST http://localhost:5000/api/complete_meeting \
  -H "Content-Type: application/json" \
  -d '{"meeting_id":1, "confirmation_token":"YOUR_TOKEN"}' \
  --user teacher1:pass1123
**********************************************************************************
Tech Stack 💻
Backend: Python + Flask + SQLite

Frontend: HTML/JS (SSE for real-time updates)

Authentication: HTTP Basic Auth for teachers
