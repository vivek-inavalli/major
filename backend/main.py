from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from bs4 import BeautifulSoup
import requests
import re
import os
import uuid
import datetime
from typing import Optional, Dict, Any, List
from pymongo import MongoClient
import spacy
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

MONGO_URL = "mongodb://localhost:27017"
DB_NAME = "privacy_auditor_db"
COLLECTION_NAME = "audits"
REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

app = FastAPI(title="AI Privacy Auditor API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = MongoClient(MONGO_URL)
db = client[DB_NAME]
audits = db[COLLECTION_NAME]

try:
    nlp = spacy.load("en_core_web_sm")
except:
    raise RuntimeError("spaCy model not found. Run: python -m spacy download en_core_web_sm")

def scrape_website_text(url: str) -> str:
    try:
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text(separator=" ")
        return text.strip()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to scrape URL: {str(e)}")

STOPWORDS = set([
    "a", "an", "the", "is", "am", "are", "was", "were", "in", "on", "at", "of", "for",
    "and", "or", "to", "from", "it", "this", "that", "with", "as", "by", "be", "been",
    "has", "have", "had", "do", "does", "did", "can", "could", "will", "would", "should"
])

def remove_emojis(text: str) -> str:
    emoji_pattern = re.compile(
        "[" 
        "\U0001F600-\U0001F64F"
        "\U0001F300-\U0001F5FF"
        "\U0001F680-\U0001F6FF"
        "\U0001F1E0-\U0001F1FF"
        "]+", flags=re.UNICODE
    )
    return emoji_pattern.sub("", text)

def clean_text(text: str) -> str:
    text = remove_emojis(text)
    text = re.sub(r"http\S+|www\S+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()

def tokenize_text(text: str) -> List[str]:
    tokens = re.findall(r"\b\w+\b", text.lower())
    return [t for t in tokens if t not in STOPWORDS]

EMAIL_REGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
PHONE_REGEX = r"\b\d{10}\b"
AADHAAR_REGEX = r"\b\d{4}\s?\d{4}\s?\d{4}\b"
PAN_REGEX = r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"
ADDRESS_REGEX = r"\b\d{1,5}\s[A-Za-z0-9\s,.-]{5,}(Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Nagar|Colony|Sector)\b"

def detect_regex_pii(text: str) -> Dict[str, List[str]]:
    return {
        "emails": list(set(re.findall(EMAIL_REGEX, text))),
        "phones": list(set(re.findall(PHONE_REGEX, text))),
        "aadhaar": list(set(re.findall(AADHAAR_REGEX, text))),
        "pan": list(set(re.findall(PAN_REGEX, text))),
        "addresses": list(set(re.findall(ADDRESS_REGEX, text, flags=re.IGNORECASE)))
    }

def detect_ner(text: str) -> Dict[str, List[str]]:
    doc = nlp(text)
    persons, orgs, gpes, dates = set(), set(), set(), set()
    for ent in doc.ents:
        if ent.label_ == "PERSON":
            persons.add(ent.text)
        elif ent.label_ == "ORG":
            orgs.add(ent.text)
        elif ent.label_ == "GPE":
            gpes.add(ent.text)
        elif ent.label_ == "DATE":
            dates.add(ent.text)
    return {
        "PERSON": list(persons),
        "ORG": list(orgs),
        "GPE": list(gpes),
        "DATE": list(dates),
    }

SCORES = {
    "emails": 8,
    "phones": 9,
    "addresses": 10,
    "GPE": 6,
    "DATE": 7,
    "ORG": 4,
    "aadhaar": 10,
    "pan": 10
}

def calculate_risk_score(detected: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    for key in ["emails", "phones", "addresses", "aadhaar", "pan"]:
        score += SCORES.get(key, 0) * len(detected["regex"].get(key, []))
    for key in ["GPE", "DATE", "ORG"]:
        score += SCORES.get(key, 0) * len(detected["ner"].get(key, []))
    # Cap the score at 100 to represent a percentage
    score = min(score, 100)
    if score <= 30:
        level = "Low"
    elif score <= 60:
        level = "Medium"
    else:
        level = "High"
    return {"score": score, "level": level}

def generate_recommendations(detected: Dict[str, Any], risk_level: str) -> List[str]:
    recs = []
    if detected["regex"]["emails"]:
        recs.append("Remove/Hide your email from public posts and profiles.")
    if detected["regex"]["phones"]:
        recs.append("Avoid sharing phone numbers publicly to prevent spam/phishing.")
    if detected["regex"]["addresses"]:
        recs.append("Remove address/location-identifying content to reduce stalking risk.")
    if detected["ner"]["GPE"]:
        recs.append("Limit posting repeated location tags/check-ins.")
    if detected["ner"]["DATE"]:
        recs.append("Avoid posting DOB or personal date references publicly.")
    if detected["ner"]["ORG"]:
        recs.append("Be careful exposing workplace/school details in public profiles.")
    if detected["regex"]["aadhaar"] or detected["regex"]["pan"]:
        recs.append("URGENT: Never expose Aadhaar/PAN publicly. Delete immediately.")
    if risk_level == "High":
        recs.append("Update privacy settings and restrict profile visibility to trusted people.")
        recs.append("Delete older posts containing personal details and review followers/friends.")
    if not recs:
        recs.append("No major privacy risks detected. Continue safe posting habits.")
    return recs

def create_pdf_report(audit_id: str, report_data: Dict[str, Any]) -> str:
    filepath = os.path.join(REPORT_DIR, f"{audit_id}.pdf")
    c = canvas.Canvas(filepath, pagesize=letter)
    width, height = letter
    y = height - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, "AI-Based Personal Privacy Audit Report")
    y -= 30
    c.setFont("Helvetica", 12)
    c.drawString(50, y, f"Audit ID: {audit_id}")
    y -= 20
    c.drawString(50, y, f"Timestamp: {report_data['timestamp']}")
    y -= 30
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, y, f"Risk Score: {report_data['risk']['score']}  |  Risk Level: {report_data['risk']['level']}")
    y -= 30
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "Detected Sensitive Information:")
    y -= 20
    c.setFont("Helvetica", 11)

    def write_list(title, items):
        nonlocal y
        c.setFont("Helvetica-Bold", 11)
        c.drawString(55, y, f"{title}:")
        y -= 15
        c.setFont("Helvetica", 11)
        if not items:
            c.drawString(70, y, "- None")
            y -= 15
        else:
            for item in items[:10]:
                c.drawString(70, y, f"- {item}")
                y -= 15
        y -= 10

    write_list("Emails", report_data["detected"]["regex"]["emails"])
    write_list("Phones", report_data["detected"]["regex"]["phones"])
    write_list("Addresses", report_data["detected"]["regex"]["addresses"])
    write_list("Aadhaar", report_data["detected"]["regex"]["aadhaar"])
    write_list("PAN", report_data["detected"]["regex"]["pan"])
    write_list("Locations (GPE)", report_data["detected"]["ner"]["GPE"])
    write_list("Organizations", report_data["detected"]["ner"]["ORG"])
    write_list("Dates", report_data["detected"]["ner"]["DATE"])

    y -= 10
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "Recommendations:")
    y -= 20
    c.setFont("Helvetica", 11)
    for rec in report_data["recommendations"]:
        c.drawString(70, y, f"- {rec}")
        y -= 15
    c.save()
    return filepath

class AuditURLRequest(BaseModel):
    url: str

class AuditTextRequest(BaseModel):
    text: str

class AuditRequest(BaseModel):
    url: Optional[str] = None
    text: Optional[str] = None

@app.get("/")
def root():
    return {"message": "AI-Based Personal Privacy Auditor API is running ✅"}

@app.post("/audit")
def audit(payload: AuditRequest):
    if payload.url:
        return audit_by_url(AuditURLRequest(url=payload.url))
    if payload.text:
        return audit_by_text(AuditTextRequest(text=payload.text))
    raise HTTPException(status_code=400, detail="Send either url or text")

@app.post("/audit/url")
def audit_by_url(payload: AuditURLRequest):
    raw_text = scrape_website_text(payload.url)
    cleaned = clean_text(raw_text)
    tokens = tokenize_text(cleaned)
    ner_data = detect_ner(cleaned)
    regex_data = detect_regex_pii(cleaned)
    detected = {"ner": ner_data, "regex": regex_data}
    risk = calculate_risk_score(detected)
    recs = generate_recommendations(detected, risk["level"])
    audit_id = str(uuid.uuid4())
    report_data = {
        "_id": audit_id,
        "source": {"type": "url", "value": payload.url},
        "timestamp": str(datetime.datetime.now()),
        "cleaned_text_preview": cleaned[:500],
        "tokens_preview": tokens[:50],
        "detected": detected,
        "risk": risk,
        "recommendations": recs
    }
    audits.insert_one(report_data)
    return {"audit_id": audit_id, "risk": risk, "detected": detected, "recommendations": recs}

@app.post("/audit/text")
def audit_by_text(payload: AuditTextRequest):
    cleaned = clean_text(payload.text)
    tokens = tokenize_text(cleaned)
    ner_data = detect_ner(cleaned)
    regex_data = detect_regex_pii(cleaned)
    detected = {"ner": ner_data, "regex": regex_data}
    risk = calculate_risk_score(detected)
    recs = generate_recommendations(detected, risk["level"])
    audit_id = str(uuid.uuid4())
    report_data = {
        "_id": audit_id,
        "source": {"type": "text", "value": "manual_input"},
        "timestamp": str(datetime.datetime.now()),
        "cleaned_text_preview": cleaned[:500],
        "tokens_preview": tokens[:50],
        "detected": detected,
        "risk": risk,
        "recommendations": recs
    }
    audits.insert_one(report_data)
    return {"audit_id": audit_id, "risk": risk, "detected": detected, "recommendations": recs}

@app.post("/audit/upload")
async def audit_by_upload(file: UploadFile = File(...)):
    content = await file.read()
    try:
        text = content.decode("utf-8", errors="ignore")
    except:
        raise HTTPException(status_code=400, detail="Could not decode file content.")
    cleaned = clean_text(text)
    tokens = tokenize_text(cleaned)
    ner_data = detect_ner(cleaned)
    regex_data = detect_regex_pii(cleaned)
    detected = {"ner": ner_data, "regex": regex_data}
    risk = calculate_risk_score(detected)
    recs = generate_recommendations(detected, risk["level"])
    audit_id = str(uuid.uuid4())
    report_data = {
        "_id": audit_id,
        "source": {"type": "upload", "value": file.filename},
        "timestamp": str(datetime.datetime.now()),
        "cleaned_text_preview": cleaned[:500],
        "tokens_preview": tokens[:50],
        "detected": detected,
        "risk": risk,
        "recommendations": recs
    }
    audits.insert_one(report_data)
    return {"audit_id": audit_id, "risk": risk, "detected": detected, "recommendations": recs}

@app.get("/audit/{audit_id}")
def get_audit(audit_id: str):
    result = audits.find_one(
        {"_id": audit_id},
        {"_id": 1, "timestamp": 1, "source": 1, "risk": 1, "detected": 1, "recommendations": 1}
    )
    if not result:
        raise HTTPException(status_code=404, detail="Audit not found")
    return result

@app.delete("/audit/{audit_id}")
def delete_audit(audit_id: str):
    result = audits.delete_one({"_id": audit_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Audit not found")
    return {"message": "Audit deleted successfully"}

@app.get("/audit")
def list_audits(limit: int = 10):
    results = list(
        audits.find({}, {"_id": 1, "timestamp": 1, "source": 1, "risk": 1})
        .sort("timestamp", -1)
        .limit(limit)
    )
    return {"audits": results}

@app.get("/audit/{audit_id}/report")
def download_report(audit_id: str):
    audit = audits.find_one({"_id": audit_id})
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    pdf_path = os.path.join(REPORT_DIR, f"{audit_id}.pdf")
    if not os.path.exists(pdf_path):
        create_pdf_report(audit_id, audit)
    return FileResponse(pdf_path, media_type="application/pdf", filename=f"privacy_report_{audit_id}.pdf")
