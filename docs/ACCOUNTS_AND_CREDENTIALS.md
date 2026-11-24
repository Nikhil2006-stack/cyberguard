# CYBERGUARD: Dummy Test Accounts & Personas

> **IMPORTANT NOTICE:** All accounts, names, telephone numbers, academic records, and emergency contacts listed below are **100% fabricated mock identities** created exclusively for controlled, authorized ethical hacking demonstrations. Under no circumstances should real personal credentials or real student records be used.

---

## 1. Summary of Demonstration Accounts

| Username | Password | Role | Persona in Demonstration | User ID | Profile ID |
|---|---|---|---|---|---|
| `admin` | `admin123` | Administrator | SOC Lead / Security Auditor | 1 | None |
| `student_a` | `student_a_pass` | Student | **Attacker Persona** (Alex Rivera) | 2 | 1 |
| `student_b` | `student_b_pass` | Student | **Victim Persona** (Bianca Chen) | 3 | 2 |

---

## 2. Detailed Profile Records

### Student A: Alex Rivera (Attacker Perspective)
- **Account Username:** `student_a`
- **Account Password:** `student_a_pass`
- **Assigned User ID:** `2`
- **Assigned Student Profile ID:** `1`
- **Student ID Code:** `STU-2026-0814`
- **Full Name:** Alex Rivera
- **Department:** Computer Science & Cybersecurity
- **Semester:** 6th Semester
- **GPA:** 3.85
- **Fee Status:** Paid - Fully Cleared
- **Phone:** `+1 (555) 019-2831`
- **Email:** `alex.rivera@college.edu`
- **Home Address:** 142 University Drive, Tech Campus
- **Emergency Contact:** Dr. Eleanor Rivera (Mother) - `+1 (555) 019-2839`
- **Confidential Remarks:** Enrolled in Ethical Hacking & Secure Coding lab. Student Council Member.
- **Account Balance:** $0.00

### Student B: Bianca Chen (Victim Perspective)
- **Account Username:** `student_b`
- **Account Password:** `student_b_pass`
- **Assigned User ID:** `3`
- **Assigned Student Profile ID:** `2`
- **Student ID Code:** `STU-2026-0922`
- **Full Name:** Bianca Chen
- **Department:** Information Security & Cryptography
- **Semester:** 6th Semester
- **GPA:** 3.96
- **Fee Status:** Paid - Fully Cleared
- **Phone:** `+1 (555) 019-8472`
- **Email:** `bianca.chen@college.edu`
- **Home Address:** 892 Oakridge Boulevard, Apt 4B
- **Emergency Contact:** Arthur Chen (Father) - `+1 (555) 019-8479`
- **Confidential Remarks:** Holds Department Research Fellowship. Emergency medical alert: Severe penicillin allergy.
- **Account Balance:** $1,450.00

---

## 3. How These Personas Are Used During Penetration Testing

1. **Step 1:** The student presenter logs in as **Student A** (`student_a`).
2. **Step 2:** The presenter accesses Student A's own profile:
   ```http
   GET /lab/vulnerable/profile/1 HTTP/1.1
   Host: localhost:5000
   Cookie: session=...
   ```
3. **Step 3:** Using **Burp Suite Repeater**, the presenter modifies the parameter from `1` to `2`:
   ```http
   GET /lab/vulnerable/profile/2 HTTP/1.1
   Host: localhost:5000
   Cookie: session=...
   ```
4. **Step 4:** The vulnerable endpoint dumps Student B's complete profile—including Bianca Chen's private phone number, emergency contact (`Arthur Chen`), and sensitive medical remarks (`Severe penicillin allergy`).
5. **Step 5:** This vividly demonstrates to teachers and classmates the real-world privacy and safety dangers of **Insecure Direct Object Reference (IDOR)** vulnerabilities.
6. **Step 6:** The presenter then changes the target to the secured endpoint:
   ```http
   GET /lab/secured/profile/2 HTTP/1.1
   Host: localhost:5000
   Cookie: session=...
   ```
7. **Step 7:** The server responds with **HTTP 403 Forbidden**, proving that the server-side ownership check blocked unauthorized access.
