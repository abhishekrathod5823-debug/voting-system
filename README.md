
#### **1. Introduction (0 to 30 seconds)**
> *"Good morning / Good afternoon Ma'am.*  
> *Today, I am presenting our project: **Student Voting System**.*  
> *Yeh ek **secure, terminal-based voting application** hai, jise humne purely **Python aur SQLite database** use karke banaya hai. Isme kisi third-party framework ki zaroorat nahi hai, yeh standard library se lightweight aur fast chalta hai."*

---

#### **2. Core Problem & Concept (30 to 60 seconds)**
> *"Is project ka main objective hai **fair, authorized aur duplicate-free voting** ensure karna.*  
> *Is system mein humne strictly **80 authorized students** ka fixed range define kiya hai — from enrollment **`12502110501001` to `12502110501080`**.*  
> *Agar koi is range ke bahar ka student register karne ki koshish karega, toh system aur database triggers use instantly **reject** kar dete hain."*

---

#### **3. Key Features & Security (60 to 90 seconds)**
> *"Ma'am, isme humne security aur integrity par khaas dhyan diya hai:*  
> 1. **Password Security:** Passwords plain text mein store nahi hote. We use salted **PBKDF2-HMAC-SHA256 hashing**. Terminal par type karte waqt visual **`*` asterisks** bhi aate hain.  
> 2. **One Student = One Vote:** Database level par **UNIQUE constraint** lagaya gaya hai, so duplicate voting is 100% impossible.  
> 3. **Fixed Candidates:** Humne 3 fixed candidates set kiye hain — **Candidate A, Candidate B, and Candidate C**."*

---

#### **4. Admin & Live Results (90 to 120 seconds)**
> *"System mein do roles hain: **Student** aur **Admin**.*  
> - **Student Dashboard:** Student apne enrollment aur 4-digit password se login karke vote cast karta hai aur apna status check kar sakta hai.  
> - **Admin Dashboard:** Admin jab chahe **real-time live results** dekh sakta hai — including total votes, voter turnout percentage, aur winner ya tie status.  
> 
> *Har step par screen automatically **clear** ho jaati hai, jisse terminal bilkul clean aur user-friendly rehta hai.*  
> 
> *Overall, it is a **secure, simple, and reliable classroom voting system**. Thank you, Ma'am!"*

---

### 💡 Quick Viva Cheat-Sheet (Agar Ma'am sawaal poochein):

| Question | Short & Smart Answer |
| :--- | :--- |
| **Which Database?** | SQLite (`sqlite3` module in Python). |
| **How duplicate vote is stopped?** | `UNIQUE(voter_id)` constraint in SQLite table + application check. |
| **How passwords are secured?** | Salted `PBKDF2` with `SHA-256` (100,000 iterations). |
| **Who can vote?** | Only 80 authorized enrollments (`12502110501001` to `12502110501080`). |
| **Testing?** | Built-in test suite chalti hai using `python main.py --test`. |
