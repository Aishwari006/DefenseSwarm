# 🛡️ Defense Swarm: AI-Powered Adaptive Security

Defense Swarm is an intelligent security prototype that uses a multi-agent AI system to detect, classify, and mitigate cyber threats in real-time. It combines **Intent Analysis** (Agent 1) with **Behavioral Velocity** (Agent 2) to make context-aware decisions (Governor Agent), implementing dynamic responses like Honeypots, Step-Up Authentication (OTP), and Active Blocking.

---

## 1️⃣ Project Setup

### Prerequisites
*   **Python 3.10+** 
*   **Azure Functions Core Tools v4** (for running the backend)
*   **Ollama** (Local LLM) or OpenAI API Key (configured in `function_app.py`)
*   **Streamlit** (for the Dashboard UI)

### Environment Setup
1.  **Clone the Repository**:
    ```bash
    git clone <repository-url>
    cd DefenseSwarm
    ```

2.  **Create a Virtual Environment**:
    ```bash
    python -m venv .venv
    # Windows
    .venv\Scripts\activate
    # Mac/Linux
    source .venv/bin/activate
    ```

3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configuration**:
    *   Ensure `local.settings.json` is present (usually auto-generated or copy from sample).
    *   Verify `BASE_URL` in `dashboard.py` and `pages/honeypot.py` points to `http://localhost:7071/api`.

---

## 2️⃣ How to Run the Project

You need **two** separate terminal windows to run the full stack.

### Terminal 1: Backend (Azure Functions)
Start the AI Agents and API Service.
```powershell
func start
```
*   **Success**: You will see the Azure Functions logo and a list of loaded functions (`ScreenerAgent`, `InvestigatorAgent`, `GovernorAgent`, `SystemLogger`).
*   *Note*: Logs have been cleaned for demo purposes. You will valid "AGENT STARTED" logs when requests are made.

### Terminal 2: Frontend (Streamlit Dashboard)
Launch the Command Center UI.
```powershell
streamlit run dashboard.py
```
*   **Success**: A browser window will open at `http://localhost:8501`.

---

## 3️⃣ Step-by-Step Testing Guide

Use the **Main Dashboard** (Swarm Fusion Engine) for these tests.

### Test Case A: SQL Injection (Immediate Block)
*   **Scenario**: Attacker tries to bypass authentication logic.
*   **Input**:
    *   **Command**: `OR 1=1` (or `users WHERE name='admin'--`)
    *   **Velocity**: `20` (Low/Normal)
*   **Reasoning**: Intent `sql_injection` is a Critical Threat (Risk 1.0).
*   **Expected Result**:
    *   **Status**: ⛔ **BLOCKED**
    *   **Message**: "Critical Risk Threshold Exceeded"
    *   **Risk Score**: 1.00

### Test Case B: Drop Database (High Velocity - Block)
*   **Scenario**: Attacker tries to delete data rapidly.
*   **Input**:
    *   **Command**: `DROP DATABASE production`
    *   **Velocity**: `100` (Max)
*   **Reasoning**: Intent `destructive` (0.85) + Velocity 1.0 (0.4) = Risk > 0.9.
*   **Expected Result**:
    *   **Status**: ⛔ **BLOCKED**
    *   **Message**: "Zero-Trust: Malicious Intent + Velocity"

### Test Case C: Drop Database (Low Velocity - OTP)
*   **Scenario**: Admin performing a risky operation slowly (Ambiguous).
*   **Input**:
    *   **Command**: `DROP DATABASE production`
    *   **Velocity**: `10` (Very Low)
*   **Reasoning**: Intent `destructive` is risky, but Low Velocity suggests caution, not immediate malice.
*   **Expected Result**:
    *   **Status**: 🟢 **TRAFFIC NORMAL (Verification Required)**
    *   **Action**: "Additional verification required – Mobile number OTP" box appears.
    *   **Verify**: Enter any number/code and click "Verify OTP".

### Test Case D: Honeypot Redirection
*   **Scenario**: Suspicious probing (high risk range 0.5 - 0.9).
*   **Input**:
    *   **Command**: `DROP DATABASE`
    *   **Velocity**: `20` (Normal)
*   **Reasoning**: Intent `destructive` (0.85) + Velocity 0.2 (~0.08) = Risk ~0.59 (Honeypot Range).
*   **Expected Result**:
    *   **Status**: ⚠️ **SUSPICIOUS (Redirecting...)**
    *   **Action**: Redirects you to the fake **Honeypot Dashboard**.

---

## 4️⃣ Honeypot-Specific Testing

Once redirected to the **Honeypot Dashboard**, the entire UI changes (Red/Black Theme).

### Test Case E: Benign Action (Dampening)
*   **Scenario**: Attacker realizes they might be watched and tries normal things.
*   **Input**:
    *   **Command**: `Sign in` (or `Read user profile`)
    *   **Velocity**: `10`
*   **Reasoning**: Credential Access / Sensitive Read are allowed in Honeypot IF velocity is low.
*   **Expected Result**:
    *   **Decision**: **ALLOW**
    *   **Log**: "✅ ACTION: DAMPENING APPLIED (Redirecting to Production)"
    *   *Note*: Simulated redirect.

### Test Case F: Malicious Action (Killer Agent)
*   **Scenario**: Attacker executes the exploit or goes fast.
*   **Input**:
    *   **Command**: `dump all passwords` (Exfiltration)
    *   **Velocity**: `60` (High)
*   **Reasoning**: Exfiltration is strictly forbidden, or Velocity > 40 is Aggressive.
*   **Expected Result**:
    *   **Decision**: **BLOCK**
    *   **Log**: "⛔ ACTION: KILLER AGENT TRIGGERED"
    *   **UI Update**: Redirects to **ACCESS BLOCKED** page with "Killer Agent Active" GIF.

---

## 5️⃣ Backend Logs for Demo

During your recording, keep the `func start` terminal visible. It will show a clean narrative:

**Sequence:**
1.  **............................................................**
2.  **🕵️ SCREENER AGENT STARTED** -> `Incoming Query: ...`
3.  **............................................................**
4.  **🧠 INVESTIGATOR AGENT STARTED** -> `Checking Velocity: ...` -> `Behavior Risk: ...`
5.  **............................................................**
6.  **⚖️ GOVERNOR AGENT STARTED** -> `Intent: ...` -> `Impact: ...`
7.  ********************************************
8.  **💥 FINAL RISK SCORE: X.XX / 1.0**
9.  **📢 DECISION: [BLOCK / ALLOW / VERIFY]**
10. **Action Log** (e.g., "Redirecting to Honeypot...")

*If inside Honeypot*:
*   You will see **🍯 HONEYPOT GOVERNOR (LOCAL)** logs appearing in the same terminal, maintaining the flow.
