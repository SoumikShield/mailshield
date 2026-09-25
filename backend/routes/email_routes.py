from fastapi import APIRouter, UploadFile, File, HTTPException
from bson import ObjectId

from services.email_parser import parse_email

from services.spf_analyzer import (
    get_spf_record,
    extract_sending_ip,
    evaluate_spf
)

from services.dkim_analyzer import (
    analyze_dkim_header,
    get_dkim_public_key,
    verify_dkim
)

from services.dmarc_analyzer import (
    get_dmarc_record,
    extract_email_domain,
    evaluate_dmarc_alignment
)

from services.sender_analyzer import (
    analyze_sender
)

from services.url_analyzer import (
    analyze_urls
)

from services.attachment_analyzer import (
    analyze_attachments
)

from services.risk_engine import (
    calculate_risk
)

from database.mongodb import emails_collection


router = APIRouter(
    prefix="/emails",
    tags=["Email"]
)


# =========================================
# UPLOAD + ANALYZE EMAIL
# =========================================

@router.post("/upload")
async def upload_email(
    file: UploadFile = File(...)
):

    if not file.filename.lower().endswith(".eml"):

        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported"
        )

    content = await file.read()

    email_data = parse_email(
        content
    )

    # -----------------------------
    # SENDER DOMAIN
    # -----------------------------

    sender = email_data.get(
        "from"
    )

    sender_domain = extract_email_domain(
        sender
    )

    # -----------------------------
    # SPF ANALYSIS
    # -----------------------------

    spf_result = None

    if sender_domain:

        spf_record = get_spf_record(
            sender_domain
        )

        sending_ip = extract_sending_ip(
            email_data[
                "security_headers"
            ].get(
                "received",
                []
            )
        )

        spf_evaluation = evaluate_spf(
            sender_domain,
            sending_ip,
            spf_record["record"]
        )

        spf_result = {

            "domain":
                sender_domain,

            "sending_ip":
                sending_ip,

            "record_status":
                spf_record["status"],

            "record":
                spf_record["record"],

            "result":
                spf_evaluation
        }

    # -----------------------------
    # DKIM ANALYSIS
    # -----------------------------

    dkim_header = email_data[
        "security_headers"
    ].get(
        "dkim_signature"
    )

    dkim_result = analyze_dkim_header(
        dkim_header
    )

    # -----------------------------
    # DKIM DNS PUBLIC KEY
    # -----------------------------

    dkim_public_key = None

    if dkim_result["present"]:

        dkim_public_key = get_dkim_public_key(
            dkim_result["domain"],
            dkim_result["selector"]
        )

    # -----------------------------
    # DKIM CRYPTOGRAPHIC VERIFICATION
    # -----------------------------

    dkim_verification = {

        "status":
            "not_present",

        "verified":
            False
    }

    if dkim_result["present"]:

        dkim_verification = verify_dkim(
            content
        )

    # -----------------------------
    # DMARC DNS ANALYSIS
    # -----------------------------

    dmarc_result = None

    if sender_domain:

        dmarc_result = get_dmarc_record(
            sender_domain
        )

    # -----------------------------
    # DMARC ALIGNMENT
    # -----------------------------

    return_path = email_data[
        "security_headers"
    ].get(
        "return_path"
    )

    spf_domain = extract_email_domain(
        return_path
    )

    dkim_domain = dkim_result.get(
        "domain"
    )

    spf_evaluation_result = "unknown"

    if spf_result:

        spf_evaluation_result = spf_result.get(
            "result",
            "unknown"
        )

    dkim_evaluation_result = "fail"

    if dkim_verification.get(
        "verified"
    ):

        dkim_evaluation_result = "pass"

    dmarc_alignment = evaluate_dmarc_alignment(

        from_domain=sender_domain,

        spf_domain=spf_domain,

        dkim_domain=dkim_domain,

        spf_result=spf_evaluation_result,

        dkim_result=dkim_evaluation_result,

        dmarc_record=dmarc_result
    )

    # -----------------------------
    # SENDER ANALYSIS
    # -----------------------------

    sender_analysis = analyze_sender(

        email_data.get("from"),

        email_data.get("reply_to")
    )

    # -----------------------------
    # URL ANALYSIS
    # -----------------------------

    url_analysis = analyze_urls(

        email_data.get(
            "urls",
            []
        )
    )

    # -----------------------------
    # ATTACHMENT ANALYSIS
    # -----------------------------

    attachment_analysis = analyze_attachments(

        email_data.get(
            "attachments",
            []
        )
    )

    # -----------------------------
    # RISK ANALYSIS
    # -----------------------------

    risk_analysis = calculate_risk(

        spf=spf_result,

        dkim=dkim_result,

        dkim_verification=dkim_verification,

        dmarc_alignment=dmarc_alignment,

        sender_analysis=sender_analysis,

        url_analysis=url_analysis,

        attachment_analysis=attachment_analysis
    )

    # -----------------------------
    # SAVE EMAIL
    # -----------------------------

    email_document = {

        "filename":
            file.filename,

        "email":
            email_data,

        "spf":
            spf_result,

        "dkim":
            dkim_result,

        "dkim_public_key":
            dkim_public_key,

        "dkim_verification":
            dkim_verification,

        "dmarc":
            dmarc_result,

        "dmarc_alignment":
            dmarc_alignment,

        "sender_analysis":
            sender_analysis,

        "url_analysis":
            url_analysis,

        "attachment_analysis":
            attachment_analysis,

        "risk_analysis":
            risk_analysis,

        "status":
            "analyzed"
    }

    result = emails_collection.insert_one(
        email_document
    )

    return {

        "message":
            "Email analyzed and saved successfully",

        "id":
            str(result.inserted_id),

        "filename":
            file.filename,

        "status":
            "analyzed",

        "email":
            email_data,

        "spf":
            spf_result,

        "dkim":
            dkim_result,

        "dkim_public_key":
            dkim_public_key,

        "dkim_verification":
            dkim_verification,

        "dmarc":
            dmarc_result,

        "dmarc_alignment":
            dmarc_alignment,

        "sender_analysis":
            sender_analysis,

        "url_analysis":
            url_analysis,

        "attachment_analysis":
            attachment_analysis,

        "risk_analysis":
            risk_analysis
    }


# =========================================
# DASHBOARD SUMMARY
# =========================================

@router.get("/dashboard/summary")
async def dashboard_summary():

    total_emails = emails_collection.count_documents({})

    safe_count = emails_collection.count_documents({

        "risk_analysis.disposition":
            "safe"

    })

    suspicious_count = emails_collection.count_documents({

        "risk_analysis.disposition":
            "suspicious"

    })

    malicious_count = emails_collection.count_documents({

        "risk_analysis.disposition":
            "malicious"

    })

    # -------------------------------------
    # HIGH RISK EMAILS
    # -------------------------------------

    high_risk_cursor = emails_collection.find({

        "risk_analysis.risk_score": {
            "$gte": 50
        }

    }).sort(
        "risk_analysis.risk_score",
        -1
    ).limit(10)

    high_risk_emails = []

    for document in high_risk_cursor:

        risk = document.get(
            "risk_analysis",
            {}
        )

        email = document.get(
            "email",
            {}
        )

        high_risk_emails.append({

            "id":
                str(document["_id"]),

            "risk_score":
                risk.get(
                    "risk_score",
                    0
                ),

            "risk_level":
                risk.get(
                    "risk_level",
                    "unknown"
                ),

            "disposition":
                risk.get(
                    "disposition",
                    "unknown"
                ),

            "from":
                email.get(
                    "from"
                ),

            "subject":
                email.get(
                    "subject"
                )
        })

    # -------------------------------------
    # RECENT EMAILS
    # -------------------------------------

    recent_cursor = emails_collection.find().sort(

        "_id",
        -1

    ).limit(10)

    recent_emails = []

    for document in recent_cursor:

        risk = document.get(
            "risk_analysis",
            {}
        )

        email = document.get(
            "email",
            {}
        )

        recent_emails.append({

            "id":
                str(document["_id"]),

            "risk_score":
                risk.get(
                    "risk_score",
                    0
                ),

            "risk_level":
                risk.get(
                    "risk_level",
                    "unknown"
                ),

            "disposition":
                risk.get(
                    "disposition",
                    "unknown"
                ),

            "from":
                email.get(
                    "from"
                ),

            "subject":
                email.get(
                    "subject"
                ),

            "date":
                email.get(
                    "date"
                )
        })

    return {

        "total_emails":
            total_emails,

        "disposition_counts": {

            "safe":
                safe_count,

            "suspicious":
                suspicious_count,

            "malicious":
                malicious_count
        },

        "high_risk_count":
            len(high_risk_emails),

        "high_risk_emails":
            high_risk_emails,

        "recent_emails":
            recent_emails
    }


# =========================================
# GET ALL EMAILS
# =========================================

@router.get("/")
async def get_all_emails():

    email_documents = emails_collection.find().sort(

        "_id",
        -1
    )

    emails = []

    for document in email_documents:

        document["_id"] = str(
            document["_id"]
        )

        emails.append(
            document
        )

    return {

        "count":
            len(emails),

        "emails":
            emails
    }


# =========================================
# GET SINGLE EMAIL
# =========================================

@router.get("/{email_id}")
async def get_email(
    email_id: str
):

    try:

        object_id = ObjectId(
            email_id
        )

    except Exception:

        raise HTTPException(

            status_code=400,

            detail="Invalid email ID"
        )

    email_document = emails_collection.find_one({

        "_id":
            object_id

    })

    if not email_document:

        raise HTTPException(

            status_code=404,

            detail="Email not found"
        )

    email_document["_id"] = str(

        email_document["_id"]

    )

    return email_document