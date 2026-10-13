#!/usr/bin/env python3
"""
=============================================================================
                  STUDENT VOTING SYSTEM (SINGLE-FILE)
=============================================================================
Features:
- Exactly 80 authorized student enrollments: 12502110501001 to 12502110501080.
- Simple student authentication: Enrollment number + 4+ digit/character password.
- No activation codes needed.
- Fixed 3 candidates: Candidate A, Candidate B, Candidate C.
- Admin can view live election results anytime.
- Clean screen transitions: Only the selected option's output and the next
  step are displayed, keeping terminal clean without old scrollback.
=============================================================================
"""

import datetime
import hashlib
import os
import secrets
import sqlite3
import sys
from typing import Optional, Tuple, Dict, Any, List

# ---------------------------------------------------------------------------
# CONSTANTS & CONFIGURATION
# ---------------------------------------------------------------------------
DB_FILENAME = "voting_system.db"
ENROLLMENT_START = 12502110501001
ENROLLMENT_END = 12502110501080
TOTAL_AUTHORIZED_STUDENTS = 80
PBKDF2_ITERATIONS = 100_000
MIN_PASSWORD_LENGTH = 4

# Fixed candidates: A, B, C
FIXED_CANDIDATES = [
    ("Candidate A", "Group A"),
    ("Candidate B", "Group B"),
    ("Candidate C", "Group C")
]

# Programmatically generate authorized enrollment list (inclusive range)
AUTHORIZED_ENROLLMENTS = [str(num) for num in range(
    ENROLLMENT_START, ENROLLMENT_END + 1)]
AUTHORIZED_ENROLLMENTS_SET = set(AUTHORIZED_ENROLLMENTS)

# Global flag to disable screen clearing & pauses during automated testing
IS_TEST_MODE = False


# ---------------------------------------------------------------------------
# TERMINAL DISPLAY & SCREEN TRANSITION HELPERS
# ---------------------------------------------------------------------------
def clear_screen() -> None:
    """Clear terminal screen so only the current screen/step is visible."""
    if not IS_TEST_MODE:
        os.system("cls" if os.name == "nt" else "clear")


def pause(prompt: str = "\nPress Enter to continue...") -> None:
    """Pause execution until user presses Enter, then returns cleanly."""
    if not IS_TEST_MODE:
        try:
            input(prompt)
        except (KeyboardInterrupt, EOFError):
            pass


# ---------------------------------------------------------------------------
# CRYPTOGRAPHY & SECURE INPUT HELPERS
# ---------------------------------------------------------------------------
def hash_password(password: str) -> Tuple[str, str]:
    """
    Hash password using salted PBKDF2-HMAC-SHA256 with 100,000 iterations.
    Returns (salt_hex, hash_hex).
    """
    salt_bytes = secrets.token_bytes(16)
    salt_hex = salt_bytes.hex()
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_bytes,
        PBKDF2_ITERATIONS
    ).hex()
    return salt_hex, pwd_hash


def verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    """Verify password against stored salt and PBKDF2 hash using timing-safe comparison."""
    try:
        salt_bytes = bytes.fromhex(salt_hex)
        computed_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt_bytes,
            PBKDF2_ITERATIONS
        ).hex()
        return secrets.compare_digest(computed_hash, expected_hash_hex)
    except Exception:
        return False


def get_secure_input(prompt: str) -> str:
    """
    Prompt for password/sensitive input.
    - On Windows consoles (PowerShell/CMD): Displays masked asterisks (*) in real time
      so the user gets clear visual feedback that keystrokes are being registered.
    - On non-TTY or redirected terminals (Git Bash, VS Code pipes): Falls back directly
      to standard input or getpass to prevent input freezing.
    """
    # 1. Fallback for non-TTY / pipe / Git Bash without winpty
    if not sys.stdin.isatty():
        try:
            return input(prompt).strip()
        except Exception:
            sys.stdout.write(prompt)
            sys.stdout.flush()
            line = sys.stdin.readline()
            return line.rstrip("\r\n")

    # 2. Windows interactive console: print asterisks (*) as user types
    if sys.platform == "win32":
        try:
            import msvcrt
            sys.stdout.write(prompt)
            sys.stdout.flush()
            pwd_chars = []
            while True:
                ch = msvcrt.getwch()
                if ch in ("\r", "\n"):
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    return "".join(pwd_chars)
                elif ch == "\x08":  # Backspace key
                    if pwd_chars:
                        pwd_chars.pop()
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                elif ch == "\x03":  # Ctrl+C
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    raise KeyboardInterrupt
                elif ch in ("\x00", "\xe0"):  # Extended / function / arrow keys
                    msvcrt.getwch()  # skip second code
                else:
                    pwd_chars.append(ch)
                    sys.stdout.write("*")
                    sys.stdout.flush()
        except Exception:
            pass

    # 3. Standard getpass fallback (e.g. Linux / macOS)
    try:
        import getpass
        return getpass.getpass(prompt)
    except Exception:
        return input(prompt).strip()


# ---------------------------------------------------------------------------
# DATABASE INITIALIZATION & SCHEMA
# ---------------------------------------------------------------------------
def get_db_connection(db_path: str = DB_FILENAME) -> sqlite3.Connection:
    """Establish database connection with foreign key enforcement enabled."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database(conn: sqlite3.Connection) -> None:
    """
    Create required tables, triggers, and seed the 3 fixed candidates (A, B, C).
    Enforces student range and max 80 student limit at database level.
    """
    with conn:
        # Migrate legacy tables from previous version if present
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(candidates);")
        cand_cols = [row[1] for row in cursor.fetchall()]
        if "election_id" in cand_cols:
            conn.execute("DROP TABLE IF EXISTS votes;")
            conn.execute("DROP TABLE IF EXISTS candidates;")
            conn.execute("DROP TABLE IF EXISTS elections;")
            conn.execute("DROP TABLE IF EXISTS activation_codes;")

        conn.executescript(f"""
        -- Users table: stores admins and registered students
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enrollment TEXT UNIQUE,
            username TEXT UNIQUE,
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin', 'student')),
            created_at TEXT NOT NULL
        );

        -- Candidates table: exactly 3 fixed candidates
        CREATE TABLE IF NOT EXISTS candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            group_name TEXT NOT NULL
        );

        -- Votes table: unique constraint ensures exactly 1 vote per student
        CREATE TABLE IF NOT EXISTS votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            voter_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
            candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
            cast_at TEXT NOT NULL
        );

        -- Database trigger: Enforce maximum of 80 registered student accounts
        CREATE TRIGGER IF NOT EXISTS trg_enforce_student_limit
        BEFORE INSERT ON users
        FOR EACH ROW
        WHEN NEW.role = 'student'
        BEGIN
            SELECT CASE
                WHEN (SELECT COUNT(*) FROM users WHERE role = 'student') >= {TOTAL_AUTHORIZED_STUDENTS}
                THEN RAISE(ABORT, 'Database safeguard: Maximum 80 registered student accounts reached.')
            END;
        END;

        -- Database trigger: Enforce student enrollment within authorized range
        CREATE TRIGGER IF NOT EXISTS trg_enforce_enrollment_range
        BEFORE INSERT ON users
        FOR EACH ROW
        WHEN NEW.role = 'student'
        BEGIN
            SELECT CASE
                WHEN CAST(NEW.enrollment AS INTEGER) < {ENROLLMENT_START} OR CAST(NEW.enrollment AS INTEGER) > {ENROLLMENT_END}
                THEN RAISE(ABORT, 'Database safeguard: Enrollment outside authorized range.')
            END;
        END;
        """)

        # Seed the 3 fixed candidates (Candidate A, Candidate B, Candidate C)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS cnt FROM candidates;")
        if cursor.fetchone()["cnt"] != 3:
            conn.execute("DELETE FROM candidates;")
            for name, grp in FIXED_CANDIDATES:
                conn.execute(
                    "INSERT INTO candidates (name, group_name) VALUES (?, ?);", (name, grp))


# ---------------------------------------------------------------------------
# AUTHENTICATION & REGISTRATION
# ---------------------------------------------------------------------------
def is_admin_created(conn: sqlite3.Connection) -> bool:
    """Check if at least one administrator account exists."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) AS cnt FROM users WHERE role = 'admin';")
    return cursor.fetchone()["cnt"] > 0


def create_first_admin(conn: sqlite3.Connection) -> None:
    """Prompt the administrator to create an account on first launch."""
    clear_screen()
    print("========================================")
    print(" FIRST TIME SETUP: CREATE ADMINISTRATOR")
    print("========================================")
    print("No administrator account was found. Please set up admin credentials.\n")

    while True:
        try:
            username = input("Enter admin username: ").strip()
            if not username or len(username) < 3:
                print("Error: Username must be at least 3 characters.\n")
                continue

            cursor = conn.cursor()
            cursor.execute(
                "SELECT id FROM users WHERE username = ?;", (username,))
            if cursor.fetchone():
                print("Error: Username is already taken.\n")
                continue

            password = get_secure_input(
                f"Enter admin password (min {MIN_PASSWORD_LENGTH} chars/digits): ")
            if len(password) < MIN_PASSWORD_LENGTH:
                print(
                    f"Error: Password must be at least {MIN_PASSWORD_LENGTH} characters/digits long.\n")
                continue

            confirm_password = get_secure_input("Confirm admin password: ")
            if password != confirm_password:
                print("Error: Passwords do not match. Please try again.\n")
                continue

            salt_hex, hash_hex = hash_password(password)
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

            with conn:
                conn.execute(
                    "INSERT INTO users (enrollment, username, password_salt, password_hash, role, created_at) "
                    "VALUES (NULL, ?, ?, ?, 'admin', ?);",
                    (username, salt_hex, hash_hex, now_iso)
                )

            print("\nAdministrator account created successfully!")
            pause("Press Enter to continue to the main menu...")
            break
        except (KeyboardInterrupt, EOFError):
            print("\nSetup cancelled. Exiting...")
            sys.exit(1)


def register_student(conn: sqlite3.Connection, default_enrollment: Optional[str] = None) -> Optional[sqlite3.Row]:
    """Student registration handler (Enrollment + Password >= 4 chars, no activation code)."""
    clear_screen()
    print("========================================")
    print("          STUDENT REGISTRATION")
    print("========================================")

    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) AS cnt FROM users WHERE role = 'student';")
    if cursor.fetchone()["cnt"] >= TOTAL_AUTHORIZED_STUDENTS:
        print("Registration closed: All 80 student accounts have already been registered.")
        pause()
        return None

    try:
        if default_enrollment:
            enrollment = default_enrollment
            print(f"Enrollment Number: {enrollment}")
        else:
            enrollment = input(
                "Enter your Enrollment Number (12502110501001 - 12502110501080): ").strip()

        # 1. Validate enrollment format and range
        if enrollment not in AUTHORIZED_ENROLLMENTS_SET:
            print(
                f"\nError: Enrollment number '{enrollment}' is not authorized.")
            print(f"Authorized range: {ENROLLMENT_START} to {ENROLLMENT_END}.")
            pause()
            return None

        # 2. Check if already registered
        cursor.execute(
            "SELECT * FROM users WHERE enrollment = ?;", (enrollment,))
        existing = cursor.fetchone()
        if existing:
            print(
                f"\nStudent with enrollment '{enrollment}' is already registered. Please login.")
            pause()
            return None

        # 3. Password setup (min 4 chars)
        password = get_secure_input(
            f"Create a password (min {MIN_PASSWORD_LENGTH} characters/digits): ")
        if len(password) < MIN_PASSWORD_LENGTH:
            print(
                f"\nError: Password must be at least {MIN_PASSWORD_LENGTH} characters/digits.")
            pause()
            return None

        confirm_pwd = get_secure_input("Confirm password: ")
        if password != confirm_pwd:
            print("\nError: Passwords do not match.")
            pause()
            return None

        salt_hex, hash_hex = hash_password(password)
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with conn:
            conn.execute(
                "INSERT INTO users (enrollment, username, password_salt, password_hash, role, created_at) "
                "VALUES (?, ?, ?, ?, 'student', ?);",
                (enrollment, enrollment, salt_hex, hash_hex, now_iso)
            )

        print("\nRegistration Successful! You can now log in and cast your vote.")
        pause("Press Enter to continue...")
        cursor.execute(
            "SELECT * FROM users WHERE enrollment = ?;", (enrollment,))
        return cursor.fetchone()
    except sqlite3.IntegrityError as e:
        print(f"\nDatabase error during registration: {e}")
        pause()
        return None
    except (KeyboardInterrupt, EOFError):
        print("\nRegistration cancelled.")
        pause()
        return None


def login(conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
    """User login handler for Admin (username) and Students (enrollment)."""
    clear_screen()
    print("========================================")
    print("                 LOGIN")
    print("========================================")
    try:
        identifier = input(
            "Username (Admin) or Enrollment Number (Student): ").strip()
        if not identifier:
            print("\nError: Identifier cannot be empty.")
            pause()
            return None

        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username = ? OR enrollment = ?;",
            (identifier, identifier)
        )
        user = cursor.fetchone()

        # If it is a valid authorized enrollment that is not registered yet:
        if not user and identifier in AUTHORIZED_ENROLLMENTS_SET:
            print(
                f"\nEnrollment '{identifier}' is valid but not yet registered.")
            reg_choice = input(
                "Would you like to register and set your password now? (y/N): ").strip().lower()
            if reg_choice == "y":
                return register_student(conn, default_enrollment=identifier)
            pause()
            return None

        if not user:
            print("\nError: Invalid username or enrollment number.")
            pause()
            return None

        password = get_secure_input("Password: ")

        if not verify_password(password, user["password_salt"], user["password_hash"]):
            print("\nError: Incorrect password.")
            pause()
            return None

        print(
            f"\nLogin successful! Welcome, {user['username']} ({user['role'].upper()}).")
        pause("Press Enter to go to Dashboard...")
        return user
    except (KeyboardInterrupt, EOFError):
        print("\nLogin cancelled.")
        pause()
        return None


# ---------------------------------------------------------------------------
# VOTING OPERATIONS (STUDENT)
# ---------------------------------------------------------------------------
def view_student_status(conn: sqlite3.Connection, current_user: sqlite3.Row) -> None:
    """Display student's current voting status."""
    clear_screen()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT v.cast_at, c.name, c.group_name
        FROM votes v
        JOIN candidates c ON v.candidate_id = c.id
        WHERE v.voter_id = ?;
    """, (current_user["id"],))
    vote_record = cursor.fetchone()

    print("========================================")
    print("          MY VOTING STATUS")
    print("========================================")
    print(f"Enrollment Number: {current_user['enrollment']}")
    if vote_record:
        print(f"Voting Status:     VOTED")
        print(
            f"Voted For:         {vote_record['name']} ({vote_record['group_name']})")
        print(f"Voted At:          {vote_record['cast_at'][:19]} UTC")
    else:
        print("Voting Status:     NOT YET VOTED")
        print("\nYou can cast your vote by selecting Option 1 from your Dashboard.")
    print("========================================")
    pause()


def cast_vote(conn: sqlite3.Connection, current_user: sqlite3.Row) -> None:
    """Cast vote for one of the 3 candidates (A, B, C)."""
    clear_screen()
    print("========================================")
    print("            CAST YOUR VOTE")
    print("========================================")

    cursor = conn.cursor()

    # Check if student already voted
    cursor.execute("SELECT id FROM votes WHERE voter_id = ?;",
                   (current_user["id"],))
    if cursor.fetchone():
        print("Notice: You have already cast your vote! Each student can vote only once.")
        print("========================================")
        pause()
        return

    # Retrieve the 3 candidates
    cursor.execute(
        "SELECT id, name, group_name FROM candidates ORDER BY id ASC;")
    candidates = cursor.fetchall()

    print("\nCandidates:")
    print("-" * 40)
    choice_map = {}
    for idx, c in enumerate(candidates, 1):
        print(f"  {idx}. {c['name']}  ({c['group_name']})")
        choice_map[str(idx)] = c
    print("-" * 40)

    try:
        choice = input("\nEnter choice (1, 2, or 3): ").strip()
        if choice not in choice_map:
            print("\nError: Invalid candidate choice. Please choose 1, 2, or 3.")
            pause()
            return

        selected_cand = choice_map[choice]

        confirm = input(
            f"\nAre you sure you want to vote for '{selected_cand['name']}'? (y/N): "
        ).strip().lower()

        if confirm != "y":
            print("\nVote cancelled. No vote recorded.")
            pause()
            return

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with conn:
            conn.execute(
                "INSERT INTO votes (voter_id, candidate_id, cast_at) VALUES (?, ?, ?);",
                (current_user["id"], selected_cand["id"], now_iso)
            )

        print(
            f"\nSuccess! Your vote for '{selected_cand['name']}' has been securely cast.")
        pause()
    except sqlite3.IntegrityError:
        print("\nError: Duplicate vote detected. You cannot vote more than once.")
        pause()
    except (KeyboardInterrupt, EOFError):
        print("\nVote cancelled.")
        pause()


# ---------------------------------------------------------------------------
# RESULTS & ADMIN DASHBOARD
# ---------------------------------------------------------------------------
def calculate_results(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Calculate live election results directly from database."""
    cursor = conn.cursor()

    # Total registered students
    cursor.execute(
        "SELECT COUNT(*) AS total_reg FROM users WHERE role = 'student';")
    total_registered = cursor.fetchone()["total_reg"]

    # Total votes cast
    cursor.execute("SELECT COUNT(*) AS total_votes FROM votes;")
    total_votes = cursor.fetchone()["total_votes"]

    not_voted = total_registered - total_votes
    turnout_pct = (total_votes / total_registered *
                   100) if total_registered > 0 else 0.0

    # Votes per candidate
    cursor.execute("""
        SELECT 
            c.id, 
            c.name, 
            c.group_name, 
            COUNT(v.id) AS vote_count
        FROM candidates c
        LEFT JOIN votes v ON c.id = v.candidate_id
        GROUP BY c.id, c.name, c.group_name
        ORDER BY c.id ASC;
    """)
    candidate_list = []
    max_votes = -1

    for row in cursor.fetchall():
        v_count = row["vote_count"]
        pct = (v_count / total_votes * 100) if total_votes > 0 else 0.0
        candidate_list.append({
            "id": row["id"],
            "name": row["name"],
            "group_name": row["group_name"],
            "vote_count": v_count,
            "percentage": pct
        })
        if v_count > max_votes:
            max_votes = v_count

    # Determine leading status
    if total_votes == 0:
        outcome = "No votes have been cast yet."
    else:
        top_cands = [c for c in candidate_list if c["vote_count"] == max_votes]
        if len(top_cands) == 1:
            w = top_cands[0]
            outcome = f"Leader / Winner: {w['name']} with {w['vote_count']} votes ({w['percentage']:.2f}%)."
        else:
            names = ", ".join(c['name'] for c in top_cands)
            outcome = f"TIE between {names} with {max_votes} votes each."

    return {
        "total_authorized": TOTAL_AUTHORIZED_STUDENTS,
        "total_registered": total_registered,
        "total_votes": total_votes,
        "not_voted": not_voted,
        "turnout_pct": turnout_pct,
        "candidates": candidate_list,
        "outcome": outcome
    }


def show_results(conn: sqlite3.Connection) -> None:
    """Display real-time / anytime election results for Admin."""
    clear_screen()
    results = calculate_results(conn)

    print("============================================================")
    print("                 ELECTION RESULTS (LIVE)")
    print("============================================================")
    print(f"Total Authorized Students:  {results['total_authorized']}")
    print(f"Total Registered Students:  {results['total_registered']}")
    print(f"Total Votes Cast:           {results['total_votes']}")
    print(f"Students Not Yet Voted:     {results['not_voted']}")
    print(f"Voter Turnout:              {results['turnout_pct']:.2f}%")
    print("-" * 60)
    print(f"{'Candidate':<18} {'Group':<14} {'Votes':<10} {'Percentage':<12}")
    print("-" * 60)
    for c in results["candidates"]:
        print(
            f"{c['name']:<18} {c['group_name']:<14} {c['vote_count']:<10} {c['percentage']:.2f}%")
    print("-" * 60)
    print(f"Current Status: {results['outcome']}")
    print("============================================================")
    pause()


def view_registered_students(conn: sqlite3.Connection) -> None:
    """Admin view: List all registered students and their voting status."""
    clear_screen()
    print("=================================================================")
    print("              REGISTERED STUDENTS & VOTING STATUS")
    print("=================================================================")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.enrollment, u.created_at, v.cast_at
        FROM users u
        LEFT JOIN votes v ON u.id = v.voter_id
        WHERE u.role = 'student'
        ORDER BY u.enrollment ASC;
    """)
    students = cursor.fetchall()

    if not students:
        print("No students have registered yet.")
        print(f"Total authorized students: {TOTAL_AUTHORIZED_STUDENTS}")
        print("=================================================================")
        pause()
        return

    print(f"Total Registered: {len(students)} / {TOTAL_AUTHORIZED_STUDENTS}")
    print("-" * 65)
    print(f"{'#':<4} {'Enrollment':<18} {'Registered At (UTC)':<22} {'Vote Status':<15}")
    print("-" * 65)
    for idx, s in enumerate(students, 1):
        v_status = "VOTED" if s["cast_at"] else "PENDING"
        print(
            f"{idx:<4} {s['enrollment']:<18} {s['created_at'][:19]:<22} {v_status:<15}")
    print("=================================================================")
    pause()


# ---------------------------------------------------------------------------
# MENUS
# ---------------------------------------------------------------------------
def admin_menu(conn: sqlite3.Connection, admin_user: sqlite3.Row) -> None:
    """Admin dashboard: view results anytime and view student status."""
    while True:
        clear_screen()
        print("========================================")
        print("           ADMIN DASHBOARD")
        print("========================================")
        print("1. View Election Results (Anytime)")
        print("2. View Registered Students & Status")
        print("3. Logout")
        print("0. Exit")
        print("========================================")

        try:
            choice = input("Enter your choice: ").strip()
            if choice == "1":
                show_results(conn)
            elif choice == "2":
                view_registered_students(conn)
            elif choice == "3":
                clear_screen()
                print("Logged out successfully.")
                pause("Press Enter to return to Main Menu...")
                break
            elif choice == "0":
                clear_screen()
                print("Exiting application. Goodbye!")
                sys.exit(0)
            else:
                print("\nInvalid choice. Please choose 1, 2, 3, or 0.")
                pause()
        except (KeyboardInterrupt, EOFError):
            break


def student_menu(conn: sqlite3.Connection, student_user: sqlite3.Row) -> None:
    """Student dashboard: cast vote and view status."""
    while True:
        clear_screen()
        print("========================================")
        print(f"   STUDENT DASHBOARD ({student_user['enrollment']})")
        print("========================================")
        print("1. Cast Vote")
        print("2. View My Voting Status")
        print("3. Logout")
        print("0. Exit")
        print("========================================")

        try:
            choice = input("Enter your choice: ").strip()
            if choice == "1":
                cast_vote(conn, student_user)
            elif choice == "2":
                view_student_status(conn, student_user)
            elif choice == "3":
                clear_screen()
                print("Logged out successfully.")
                pause("Press Enter to return to Main Menu...")
                break
            elif choice == "0":
                clear_screen()
                print("Exiting application. Goodbye!")
                sys.exit(0)
            else:
                print("\nInvalid choice. Please choose 1, 2, 3, or 0.")
                pause()
        except (KeyboardInterrupt, EOFError):
            break


def main_menu(conn: sqlite3.Connection) -> None:
    """Main application landing menu."""
    while True:
        clear_screen()
        print("========================================")
        print("       STUDENT VOTING SYSTEM")
        print("========================================")
        print("1. Login (Admin / Student)")
        print("2. Student Registration (Set Password)")
        print("0. Exit")
        print("========================================")

        try:
            choice = input("Enter your choice: ").strip()
            if choice == "1":
                user = login(conn)
                if user:
                    if user["role"] == "admin":
                        admin_menu(conn, user)
                    else:
                        student_menu(conn, user)
            elif choice == "2":
                register_student(conn)
            elif choice == "0":
                clear_screen()
                print("Exiting application. Goodbye!")
                break
            else:
                print("\nInvalid choice. Please enter 1, 2, or 0.")
                pause()
        except (KeyboardInterrupt, EOFError):
            clear_screen()
            print("Exiting application. Goodbye!")
            break


# ---------------------------------------------------------------------------
# SELF-TEST SUITE (--test mode)
# ---------------------------------------------------------------------------
def run_tests() -> None:
    """
    Automated self-test suite running on an isolated in-memory SQLite database.
    Tests:
    - 80 authorized enrollments range
    - Minimum 4-character password requirement
    - Rejection of invalid enrollments
    - Student registration without activation codes
    - Fixed 3 candidates (A, B, C)
    - Casting votes and duplicate vote rejection
    - Admin viewing results anytime
    - Turnout and tie calculations
    """
    global IS_TEST_MODE
    IS_TEST_MODE = True

    print("\n" + "=" * 60)
    print("      RUNNING STUDENT VOTING SYSTEM SELF-TEST SUITE")
    print("=" * 60)

    conn = sqlite3.connect(":memory:")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    initialize_database(conn)

    passed_tests = 0
    total_tests = 0

    def assert_test(condition: bool, description: str) -> None:
        nonlocal passed_tests, total_tests
        total_tests += 1
        if condition:
            passed_tests += 1
            print(f" [PASS] Test {total_tests:02d}: {description}")
        else:
            print(f" [FAIL] Test {total_tests:02d}: {description}")
            raise AssertionError(f"Test Failed: {description}")

    # 1. Test 80 authorized enrollment numbers
    assert_test(len(AUTHORIZED_ENROLLMENTS) == 80,
                "Programmatically generated 80 authorized enrollments")
    assert_test(AUTHORIZED_ENROLLMENTS[0] == "12502110501001",
                "Starting enrollment matches 12502110501001")
    assert_test(AUTHORIZED_ENROLLMENTS[-1] == "12502110501080",
                "Ending enrollment matches 12502110501080")

    # 2. Test invalid enrollments rejected
    for inv in ["12502110501000", "12502110501081", "999999", "admin"]:
        assert_test(inv not in AUTHORIZED_ENROLLMENTS_SET,
                    f"Enrollment {inv} is rejected")

    # 3. Test 4-digit / character password hashing
    salt, p_hash = hash_password("1234")
    assert_test(verify_password("1234", salt, p_hash),
                "4-digit password '1234' verified successfully")
    assert_test(not verify_password("0000", salt, p_hash),
                "Wrong password rejected")

    # 4. Test fixed 3 candidates
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM candidates ORDER BY id ASC;")
    cands = cursor.fetchall()
    assert_test(len(cands) == 3, "Exactly 3 fixed candidates initialized")
    assert_test(cands[0]["name"] == "Candidate A", "Candidate A exists")
    assert_test(cands[1]["name"] == "Candidate B", "Candidate B exists")
    assert_test(cands[2]["name"] == "Candidate C", "Candidate C exists")

    # 5. Test Admin creation
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    adm_salt, adm_hash = hash_password("admin123")
    conn.execute(
        "INSERT INTO users (enrollment, username, password_salt, password_hash, role, created_at) "
        "VALUES (NULL, 'admin_user', ?, ?, 'admin', ?);",
        (adm_salt, adm_hash, now_iso)
    )
    assert_test(is_admin_created(conn), "Admin account exists in database")

    # 6. Test student registration (no activation code needed)
    first_enr = AUTHORIZED_ENROLLMENTS[0]
    st_salt, st_hash = hash_password("pass")
    conn.execute(
        "INSERT INTO users (enrollment, username, password_salt, password_hash, role, created_at) "
        "VALUES (?, ?, ?, ?, 'student', ?);",
        (first_enr, first_enr, st_salt, st_hash, now_iso)
    )
    cursor.execute("SELECT * FROM users WHERE enrollment = ?;", (first_enr,))
    st_user = cursor.fetchone()
    assert_test(st_user is not None,
                f"Student {first_enr} registered successfully")

    # 7. Test duplicate registration prevention
    dup_failed = False
    try:
        conn.execute(
            "INSERT INTO users (enrollment, username, password_salt, password_hash, role, created_at) "
            "VALUES (?, ?, ?, ?, 'student', ?);",
            (first_enr, first_enr, st_salt, st_hash, now_iso)
        )
    except sqlite3.IntegrityError:
        dup_failed = True
    assert_test(
        dup_failed, "Duplicate student registration prevented by UNIQUE constraint")

    # 8. Test out-of-range enrollment rejected by trigger
    range_failed = False
    try:
        conn.execute(
            "INSERT INTO users (enrollment, username, password_salt, password_hash, role, created_at) "
            "VALUES ('12502110501000', '12502110501000', ?, ?, 'student', ?);",
            (st_salt, st_hash, now_iso)
        )
    except sqlite3.DatabaseError:
        range_failed = True
    assert_test(
        range_failed, "Enrollment below 12502110501001 blocked by database trigger")

    # 9. Test admin can view results anytime (even with zero votes)
    results_zero = calculate_results(conn)
    assert_test(results_zero["total_votes"] == 0,
                "Admin can view zero-vote results anytime")
    assert_test(
        "No votes have been cast" in results_zero["outcome"], "Correct zero-vote message")

    # 10. Student casts vote for Candidate A
    cand_a_id = cands[0]["id"]
    conn.execute(
        "INSERT INTO votes (voter_id, candidate_id, cast_at) VALUES (?, ?, ?);",
        (st_user["id"], cand_a_id, now_iso)
    )
    cursor.execute("SELECT COUNT(*) AS cnt FROM votes;")
    assert_test(cursor.fetchone()["cnt"] == 1,
                "Vote recorded successfully for Candidate A")

    # 11. Test duplicate voting rejected (1 student = 1 vote)
    dup_vote_failed = False
    try:
        conn.execute(
            "INSERT INTO votes (voter_id, candidate_id, cast_at) VALUES (?, ?, ?);",
            (st_user["id"], cands[1]["id"], now_iso)
        )
    except sqlite3.IntegrityError:
        dup_vote_failed = True
    assert_test(dup_vote_failed, "Duplicate vote rejected by UNIQUE(voter_id)")

    # 12. Register second student and vote for Candidate B (testing tie)
    second_enr = AUTHORIZED_ENROLLMENTS[1]
    conn.execute(
        "INSERT INTO users (enrollment, username, password_salt, password_hash, role, created_at) "
        "VALUES (?, ?, ?, ?, 'student', ?);",
        (second_enr, second_enr, st_salt, st_hash, now_iso)
    )
    cursor.execute("SELECT id FROM users WHERE enrollment = ?;", (second_enr,))
    st_user2_id = cursor.fetchone()["id"]
    conn.execute(
        "INSERT INTO votes (voter_id, candidate_id, cast_at) VALUES (?, ?, ?);",
        (st_user2_id, cands[1]["id"], now_iso)
    )

    # 13. Test admin can view live results anytime with tie detection
    live_results = calculate_results(conn)
    assert_test(live_results["total_votes"] == 2,
                "Live results show 2 total votes")
    assert_test("TIE" in live_results["outcome"],
                "Live results accurately detect tie between Candidate A & B")

    print("\n" + "=" * 60)
    print(f" ALL TESTS PASSED! ({passed_tests}/{total_tests} tests succeeded)")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# MAIN ENTRYPOINT
# ---------------------------------------------------------------------------
def main() -> None:
    """Application main entry point."""
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        try:
            run_tests()
            sys.exit(0)
        except AssertionError as e:
            print(f"\nSelf-test failed: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"\nUnexpected error during self-test: {e}")
            sys.exit(1)

    conn = get_db_connection(DB_FILENAME)
    initialize_database(conn)

    # First run setup for admin if none exists
    if not is_admin_created(conn):
        create_first_admin(conn)

    try:
        main_menu(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
