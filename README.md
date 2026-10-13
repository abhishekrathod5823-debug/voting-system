# ACADEMIC PROJECT REPORT
## Student Voting System: A Secure Terminal-Based Ballot Application

---

**Project Title:** Student Voting System  
**Language & Platform:** Python 3 (Standard Library) & SQLite 3  
**Architecture:** Single-File Console Application (`main.py`)  
**Target Users:** 80 Authorized Classroom Students (`12502110501001` – `12502110501080`)  

---

### TABLE OF CONTENTS
1. [Abstract](#1-abstract)
2. [Introduction & Problem Statement](#2-introduction--problem-statement)
3. [System Architecture & Technology Stack](#3-system-architecture--technology-stack)
4. [Database Design & Integrity Constraints](#4-database-design--integrity-constraints)
5. [Security & Cryptographic Implementation](#5-security--cryptographic-implementation)
6. [Operational Workflow & User Interaction](#6-operational-workflow--user-interaction)
7. [Automated Testing & Verification](#7-automated-testing--verification)
8. [Limitations & Future Enhancements](#8-limitations--future-enhancements)
9. [Conclusion](#9-conclusion)

---

### 1. Abstract
The **Student Voting System** is a lightweight, high-integrity terminal application engineered to conduct small-scale classroom elections with mathematical precision, tamper resistance, and zero external software dependencies. Built completely in standard Python 3 and SQLite, the system establishes a strictly controlled voting cohort restricted to 80 authorized students (Enrollment Nos. `12502110501001` to `12502110501080`). 

The architecture guarantees the **"One Student, One Vote"** democratic principle using multi-layered enforcement: application business logic, cryptographic password hashing (PBKDF2-HMAC-SHA256), and relational database constraints and triggers. The administrative module allows real-time live result tabulation, voter turnout calculations, and automatic tie detection, while maintaining an uncluttered terminal interface through intelligent screen buffer transitions.

---

### 2. Introduction & Problem Statement

#### 2.1 Background
Conventional paper ballots in academic institutions and classroom elections suffer from several operational bottlenecks:
- Significant manual tallying overhead and susceptibility to human counting errors.
- Risk of duplicate ballots and unauthorized votes.
- Lack of immediate auditability and live turnout tracking.
- High paper consumption for routine representative elections.

#### 2.2 Problem Statement
There is a need for a self-contained, offline-first digital voting system that requires **no external dependencies**, runs immediately on any standard operating system with Python installed, automatically prevents out-of-range student registrations, and permanently eliminates duplicate voting through database-level integrity safeguards.

#### 2.3 Core Project Objectives
- **Strict Boundary Control:** Only the pre-defined 80 students (`12502110501001`–`12502110501080`) are permitted to participate; all other enrollments are blocked.
- **Fixed Candidates:** Support a structured race between 3 designated candidates: **Candidate A**, **Candidate B**, and **Candidate C**.
- **Cryptographic Security:** Salted PBKDF2-HMAC-SHA256 password hashing with masked console input (`*` asterisks).
- **Relational Integrity:** SQLite `UNIQUE(voter_id)` constraints and automated trigger validations.
- **Anytime Administrative Tabulation:** Live election report generation accessible on demand by the administrator.

---

### 3. System Architecture & Technology Stack

The entire application follows a modular, monolithic architecture implemented within a single executable file (`main.py`).

#### 3.1 Technology Stack Details
- **Programming Language:** Python 3.10+
- **Persistence Engine:** Embedded SQLite 3 (`sqlite3`)
- **Cryptography:** Python Standard `hashlib` (PBKDF2-HMAC-SHA256) and `secrets` (CSPRNG salt generation)
- **Console Manipulation:** Python `os`, `sys`, and Windows `msvcrt` for interactive character masking.

---

### 4. Database Design & Integrity Constraints

The SQLite database file `voting_system.db` is generated automatically on initialization with foreign key constraints enabled (`PRAGMA foreign_keys = ON;`).

#### 4.1 Relational Schema

```sql
-- 1. Users Table (Administrators and Students)
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enrollment TEXT UNIQUE,             -- NULL for admin; fixed range for students
    username TEXT UNIQUE,               -- Administrator username
    password_salt TEXT NOT NULL,        -- 16-byte random hex salt
    password_hash TEXT NOT NULL,        -- PBKDF2-HMAC-SHA256 derived key
    role TEXT NOT NULL CHECK(role IN ('admin', 'student')),
    created_at TEXT NOT NULL
);

-- 2. Candidates Table (Pre-seeded with Candidate A, B, and C)
CREATE TABLE candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,          -- 'Candidate A', 'Candidate B', 'Candidate C'
    group_name TEXT NOT NULL            -- 'Group A', 'Group B', 'Group C'
);

-- 3. Votes Table (One Vote Per Student Enforcement)
CREATE TABLE votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    voter_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
    cast_at TEXT NOT NULL
);
```

#### 4.2 Database Triggers for Hard Enforcement
To ensure constraints cannot be bypassed even if application-level checks fail, two triggers are active in the database:

1. **Cohort Limit Trigger:** Rejects any `INSERT` on `users` if the total count of registered students reaches or exceeds 80.
```sql
CREATE TRIGGER trg_enforce_student_limit
BEFORE INSERT ON users FOR EACH ROW WHEN NEW.role = 'student'
BEGIN
    SELECT CASE
        WHEN (SELECT COUNT(*) FROM users WHERE role = 'student') >= 80
        THEN RAISE(ABORT, 'Database safeguard: Maximum 80 registered student accounts reached.')
    END;
END;
```

2. **Enrollment Boundary Trigger:** Verifies that the student's enrollment integer falls within `12502110501001` and `12502110501080`.
```sql
CREATE TRIGGER trg_enforce_enrollment_range
BEFORE INSERT ON users FOR EACH ROW WHEN NEW.role = 'student'
BEGIN
    SELECT CASE
        WHEN CAST(NEW.enrollment AS INTEGER) < 12502110501001 
          OR CAST(NEW.enrollment AS INTEGER) > 12502110501080
        THEN RAISE(ABORT, 'Database safeguard: Enrollment outside authorized range.')
    END;
END;
```

---

### 5. Security & Cryptographic Implementation

#### 5.1 Password Hashing Mechanism
Passwords are never stored in plaintext. The system implements the industry-standard **PBKDF2** key derivation function:
$$\text{Hash} = \text{PBKDF2-HMAC-SHA256}(\text{Password}, \text{Salt}, \text{Iterations} = 100\,000)$$
- **Salt Generation:** A 16-byte cryptographically secure random number generated via `secrets.token_bytes(16)`.
- **Timing-Attack Resistance:** Password comparison uses `secrets.compare_digest()` to eliminate timing discrepancies.
- **Minimum Complexity:** Passwords must be at least 4 characters/digits long, allowing students to use memorable PINs (e.g., `1234`) while maintaining cryptographic protection against brute-force attacks.

#### 5.2 Real-Time Password Masking
To prevent shoulder-surfing while providing clear visual confirmation of typing:
- Uses `msvcrt.getwch()` on Windows consoles to capture keystrokes individually.
- Prints `*` for each character typed.
- Supports the `Backspace` key (`\x08`), cleanly erasing asterisks from the terminal screen (`\b \b`).
- Gracefully falls back to standard input in non-TTY/piped environments.

#### 5.3 Educational Disclaimer on Ballot Secrecy
> This system is designed as an educational classroom application. Because the `votes` table references `voter_id` directly to mathematically enforce the single-vote constraint, database administrators can correlate voters with candidate selections. True public-election systems require cryptographically blind signatures or homomorphic encryption to achieve anonymity.

---

### 6. Operational Workflow & User Interaction

The user experience is optimized with a clean page-transition model. Old screen output is cleared via `clear_screen()`, and results are paused with `pause()` before returning to the dashboard.

#### 6.1 Key Screen Formats

##### A. Main Landing Menu
```text
========================================
       STUDENT VOTING SYSTEM
========================================
1. Login (Admin / Student)
2. Student Registration (Set Password)
0. Exit
========================================
```

##### B. Student Voting Interface
```text
========================================
            CAST YOUR VOTE
========================================
Candidates:
----------------------------------------
  1. Candidate A  (Group A)
  2. Candidate B  (Group B)
  3. Candidate C  (Group C)
----------------------------------------
Enter choice (1, 2, or 3): 1
Are you sure you want to vote for 'Candidate A'? (y/N): y

Success! Your vote for 'Candidate A' has been securely cast.
Press Enter to continue...
```

##### C. Admin Live Results Dashboard
```text
============================================================
                 ELECTION RESULTS (LIVE)
============================================================
Total Authorized Students:  80
Total Registered Students:  42
Total Votes Cast:           40
Students Not Yet Voted:     2
Voter Turnout:              95.24%
------------------------------------------------------------
Candidate          Group          Votes      Percentage  
------------------------------------------------------------
Candidate A        Group A        20         50.00%      
Candidate B        Group B        15         37.50%      
Candidate C        Group C        5          12.50%      
------------------------------------------------------------
Current Status: Leader / Winner: Candidate A with 20 votes (50.00%).
============================================================
```

---

### 7. Automated Testing & Verification

The application includes an internal automated test suite executed via the CLI command:
```powershell
python main.py --test
```

#### 7.1 Test Strategy
Testing executes against an isolated, transient in-memory SQLite database (`:memory:`), ensuring that zero test artifacts pollute the real database (`voting_system.db`).

#### 7.2 Summary of Test Suite Results (23 Test Cases)

| Test ID | Test Scenario | Verified Condition | Status |
| :---: | :--- | :--- | :---: |
| **01–03** | Enrollment Range Boundary | Validates 80 entries from `12502110501001` to `12502110501080` | **PASS** |
| **04–07** | Out-of-Boundary Enrollments | Rejects below range, above range, invalid alphanumeric IDs | **PASS** |
| **08–09** | Cryptographic Verification | Tests PBKDF2 hash validity and wrong password rejection | **PASS** |
| **10–13** | Pre-seeded Candidates | Confirms Candidate A, Candidate B, Candidate C exist | **PASS** |
| **14** | Admin Account Creation | Confirms admin credentials persistence in `users` | **PASS** |
| **15–16** | Student Registration & Uniqueness | Verifies valid enrollment registers; duplicate registration fails | **PASS** |
| **17** | Trigger Boundary Check | DB trigger halts out-of-range student insertion | **PASS** |
| **18–19** | Zero-Vote Results Handling | Ensures turnout division-by-zero is handled safely | **PASS** |
| **20–21** | Single Vote & Duplicate Vote Halt | Confirms vote writes once; duplicate attempt triggers UNIQUE error | **PASS** |
| **22–23** | Live Results & Tie Detection | Correctly tabulates vote totals and reports tie between candidates | **PASS** |

**Execution Result:** `ALL TESTS PASSED! (23/23 tests succeeded)`

---

### 8. Limitations & Future Enhancements

#### 8.1 Limitations
- **Terminal Only:** Does not provide a web-based GUI (by architectural requirement).
- **Relational Ballot Link:** `votes.voter_id` directly references `users.id` to enforce uniqueness, which restricts true cryptographic ballot anonymity.

#### 8.2 Future Enhancements
- **Anonymized Ring Signatures / Blind Signatures:** Decouple voter identity from ballot recording while mathematically preserving the single-vote invariant.
- **Biometric or OTP Multi-Factor Authentication:** Implement institutional email or SMS verification during registration.
- **Audit Receipt Generation:** Provide each student with an encrypted hash receipt to independently verify their vote's inclusion in final tallies.

---

### 9. Conclusion
The **Student Voting System** demonstrates that robust, secure, and user-friendly software does not require complex frameworks or heavy third-party dependencies. By leveraging the foundational strengths of the Python standard library and SQLite's ACID-compliant transactional engine, the system delivers an efficient election solution for academic cohorts. The combination of strict boundary validation, cryptographic password security, automated database triggers, and a clean terminal workflow makes this project an exemplary prototype for modern educational ballot management.
