# MailShield

**Email Threat Detection & Investigation Platform**

MailShield is a security-focused email analysis platform that takes an `.eml` file and turns it into an investigation report.

It parses the email, checks authentication mechanisms such as SPF, DKIM and DMARC, examines the sender and URLs, checks attachments for suspicious characteristics, queries URLhaus for URL threat intelligence, and combines the results into a risk score.

The project is built around a simple idea: instead of checking each email security indicator manually, collect the relevant evidence in one place and make it easier to investigate.

---

## What MailShield does

A typical investigation looks like this:

```text
.eml file
   │
   ▼
Email Parser
   │
   ├── Sender / Reply-To
   ├── Security Headers
   ├── URLs / Domains / IPs
   └── Attachments
   │
   ▼
Security Analysis
   │
   ├── SPF
   ├── DKIM
   ├── DMARC
   ├── Sender Analysis
   ├── URL Analysis
   ├── URLhaus
   └── Attachment Analysis
   │
   ▼
Risk Engine
   │
   ├── Risk Score
   ├── Risk Level
   ├── Disposition
   └── Detection Signals
   │
   ▼
MongoDB
   │
   ▼
Dashboard / Investigation View
```

---

## Features

### Email parsing

MailShield accepts `.eml` files and extracts useful information from the message.

The parser currently extracts:

* From
* To
* Subject
* Date
* Reply-To
* Email body
* URLs
* Domains
* IP addresses
* Attachments
* Authentication-Results
* Received headers
* Return-Path
* Message-ID
* X-Originating-IP
* DKIM-Signature

Only `.eml` files are accepted by the upload endpoint.

---

### SPF analysis

MailShield retrieves the sender domain's SPF record and evaluates the sending IP against the record.

The analysis includes:

* SPF record lookup
* Sending IP extraction
* SPF record status
* SPF result
* Domain information

The application can identify results such as:

* Pass
* Fail
* SoftFail
* Not available

---

### DKIM analysis

The DKIM module performs several checks instead of simply looking for the existence of a DKIM header.

It handles:

* DKIM-Signature parsing
* DKIM domain extraction
* Selector extraction
* DNS public-key lookup
* Cryptographic DKIM verification

This allows the investigation page to show both the DKIM information present in the message and the verification result.

---

### DMARC analysis

MailShield retrieves the DMARC policy for the sender domain and analyzes the relationship between the relevant authentication domains.

The module handles:

* DMARC DNS record lookup
* Policy extraction
* `p`
* `sp`
* `pct`
* `rua`
* `ruf`
* `adkim`
* `aspf`
* SPF alignment
* DKIM alignment
* DMARC result

Both relaxed and strict alignment modes are supported.

---

### Sender analysis

The sender is checked for indicators that may be useful during an email investigation.

MailShield analyzes:

* Sender domain
* Display name
* Trusted-brand display names
* Display-name impersonation
* Lookalike domains
* Character substitutions
* Domain similarity

For example, a domain using a substitution such as:

```text
micros0ft.com
```

can be identified as a potential lookalike of:

```text
microsoft.com
```

This is treated as an investigation signal rather than automatically proving that an email is malicious.

---

### URL analysis

URLs extracted from the email are inspected for common suspicious characteristics.

The analysis checks for:

* HTTP URLs
* IP-address-based URLs
* `@` characters
* Very long URLs
* Excessive subdomains
* URL shorteners
* Suspicious URL keywords

Each URL can therefore be examined independently as part of the investigation.

---

### URLhaus threat intelligence

MailShield also integrates **URLhaus** for URL threat intelligence.

URLs extracted from an email can be checked against URLhaus data so that known malicious URLs can contribute additional evidence to the investigation.

URLhaus is used as a threat-intelligence source alongside the application's own URL analysis.

---

### Attachment analysis

Attachments are analyzed based on their filenames and extensions.

MailShield identifies potentially risky attachment types including:

* `.exe`
* `.scr`
* `.bat`
* `.cmd`
* `.dll`
* `.msi`
* `.ps1`
* `.vbs`
* `.js`
* `.hta`
* `.jar`
* `.lnk`
* `.reg`
* `.iso`
* `.img`

It also identifies:

* Macro-enabled documents
* Archive files
* Double extensions

For example:

```text
invoice.pdf.exe
```

can be flagged as a double-extension indicator.

The investigation page shows the attachment filename, extension, status and detected reasons.

---

## Risk engine

The different analysis results are combined by a heuristic risk engine.

The engine considers signals from:

* SPF
* DKIM
* DMARC
* Sender analysis
* URL analysis
* Attachment analysis

The result contains:

* Risk score
* Risk level
* Final disposition
* Number of detection signals
* Individual detection signals

The score is capped at 100.

The purpose of the risk engine is to provide an investigation-oriented summary rather than claim that a single indicator is enough to determine whether an email is malicious.

---

## Dashboard

The MailShield dashboard provides an overview of analyzed emails.

It includes:

* Total analyzed emails
* Safe / suspicious / malicious distribution
* High-risk activity
* Recent investigations
* Security-analysis telemetry
* Email investigation links
* `.eml` upload interface

The dashboard is designed around a SOC-style workflow where an analyst can quickly identify an email and open its investigation.

---

## Investigation view

Each analyzed email has its own investigation page.

The page contains:

### Message information

* Sender
* Recipient
* Subject
* Reply-To
* Date
* Message ID
* Filename
* Analysis status

### Authentication

* SPF
* DKIM
* DKIM verification
* DMARC
* Domain alignment

### Sender intelligence

* Sender domain
* Display-name analysis
* Lookalike indicators

### URL intelligence

* Extracted URLs
* URL analysis
* Suspicious URL indicators
* URLhaus results

### Attachment intelligence

* Attachment count
* Suspicious attachment count
* Individual attachment results
* Detected reasons

### Security headers

Relevant email security headers can be viewed directly during the investigation.

### Email body

The parsed message body is available from the investigation page.

### Risk summary

The investigator can see:

* Risk score
* Risk level
* Final disposition
* Detection signal count
* Individual signals

### Investigation timeline

The investigation page presents the analysis as a sequence:

```text
Email Received
      ↓
Sender Analysis
      ↓
SPF Authentication
      ↓
DKIM Verification
      ↓
DMARC Alignment
      ↓
URL Intelligence
      ↓
Attachment Analysis
      ↓
Risk Engine
      ↓
Final Disposition
```

---

## Technology stack

### Backend

* Python
* FastAPI
* Uvicorn
* PyMongo
* Python `email` package
* dnspython
* dkimpy
* Requests

### Database

* MongoDB
* MongoDB Atlas

### Frontend

* HTML
* CSS
* JavaScript

### Threat intelligence

* URLhaus

---

## Project structure

```text
mailshield/
│
├── backend/
│   │
│   ├── main.py
│   ├── config.py
│   │
│   ├── database/
│   │   └── mongodb.py
│   │
│   ├── models/
│   │   └── email_model.py
│   │
│   ├── routes/
│   │   └── email_routes.py
│   │
│   └── services/
│       ├── email_parser.py
│       ├── spf_analyzer.py
│       ├── dkim_analyzer.py
│       ├── dmarc_analyzer.py
│       ├── sender_analyzer.py
│       ├── url_analyzer.py
│       ├── urlhaus_analyzer.py
│       ├── attachment_analyzer.py
│       └── risk_engine.py
│
├── frontend/
│   ├── index.html
│   ├── style.css
│   ├── app.js
│   ├── investigation.html
│   └── investigation.js
│
├── samples/
│
├── .env
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Running the project locally

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd mailshield
```

### 2. Create a virtual environment

Windows:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.venv\Scripts\activate
```

### 3. Install dependencies

```powershell
pip install -r requirements.txt
```

### 4. Configure MongoDB

Create a `.env` file in the project root:

```env
MONGO_URI=your_mongodb_connection_string
```

Do not commit this file to GitHub.

### 5. Start the backend

Move into the backend directory:

```powershell
cd backend
```

Run:

```powershell
python -m uvicorn main:app --reload
```

The API will be available at:

```text
http://127.0.0.1:8000
```

FastAPI's interactive API documentation is available at:

```text
http://127.0.0.1:8000/docs
```

---

## API endpoints

### Health check

```http
GET /
```

```http
GET /health
```

### Upload and analyze an email

```http
POST /emails/upload
```

The endpoint accepts an `.eml` file.

### Get all analyzed emails

```http
GET /emails/
```

### Get one investigation

```http
GET /emails/{email_id}
```

---

## MongoDB

MailShield uses MongoDB to store analyzed email investigations.

The main database is:

```text
mailshield
```

The email collection is:

```text
emails
```

Each investigation stores the parsed email together with the results from the individual security-analysis modules and the final risk analysis.

---

## Security considerations

The project is designed for analyzing email samples and demonstrating email-security investigation techniques.

It should not be treated as a replacement for a production secure-email gateway or enterprise SIEM.

The `.env` file should never be committed to a public repository.

When working with real emails, sensitive information such as:

* Email addresses
* Message contents
* Internal IP addresses
* Authentication headers
* Attachments

should be handled appropriately.

---

## Current limitations

MailShield is intentionally a practical investigation project rather than a complete email-security product.

### SPF

The current SPF evaluator handles common mechanisms but is not a complete RFC-compliant SPF implementation. It does not fully implement mechanisms such as `include`, `a`, `mx`, `exists`, redirects and the complete DNS lookup-limit logic.

### Sending IP

The current sending-IP extraction uses information from `Received` headers. It is a simplified approach and should not be considered equivalent to extracting the actual SMTP connection information from a mail server.

### DMARC

An `.eml` file does not preserve the SMTP envelope `MAIL FROM` in the same way a receiving mail server has access to it.

For this reason, the application uses `Return-Path` as a proxy when evaluating SPF-domain alignment.

### Risk scoring

The risk engine is heuristic.

A high score means that multiple suspicious indicators were identified; it does not independently prove that an email is malicious.

Some related indicators can also contribute to the score at the same time.

### Attachment analysis

Attachment analysis currently focuses on filenames and extensions. It does not execute files, perform sandbox analysis or inspect the internal contents of an attachment.

### URL analysis

The URL analyzer identifies suspicious characteristics and uses URLhaus threat intelligence. It does not replace a full browser sandbox or malware-analysis environment.

---

## Why I built this

Email security is a good example of how different security signals need to be considered together.

An SPF failure by itself does not tell the whole story. The sender domain, DKIM result, DMARC alignment, URLs, attachments and other indicators provide additional context.

MailShield was built to bring these checks together into one investigation workflow.

The project also gave me hands-on experience with:

* Email security
* SPF / DKIM / DMARC
* DNS lookups
* Threat intelligence
* URL analysis
* Security automation
* Risk scoring
* REST APIs
* MongoDB
* FastAPI
* Frontend/backend integration
* SOC-style investigation workflows

---

## Future improvements

Possible future work includes:

* More complete SPF evaluation
* Deeper attachment inspection
* Additional threat-intelligence sources
* Message authentication improvements
* User authentication and access control
* SIEM integration
* Automated reporting
* More advanced URL and domain reputation analysis

These are not required for the current version of the project.

---

## Status

**Current version: Functional**

MailShield currently supports the complete basic workflow:

```text
Upload .eml
    ↓
Parse
    ↓
Analyze
    ↓
Calculate risk
    ↓
Store in MongoDB
    ↓
Display on dashboard
    ↓
Open investigation
```

The project is currently focused on email investigation rather than adding an increasing number of security features.
