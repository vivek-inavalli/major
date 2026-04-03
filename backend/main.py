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
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

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

nlp = spacy.load("en_core_web_sm")

STOPWORDS = set([
    "a","an","the","is","am","are","was","were","in","on","at","of","for",
    "and","or","to","from","it","this","that","with","as","by","be","been",
    "has","have","had","do","does","did","can","could","will","would","should"
])

EMAIL_REGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
PHONE_REGEX = r"\b\d{10}\b"
AADHAAR_REGEX = r"\b\d{4}\s?\d{4}\s?\d{4}\b"
PAN_REGEX = r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"
ADDRESS_REGEX = r"\b\d{1,5}\s[A-Za-z0-9\s,.-]{5,}(Street|St|Road|Rd|Avenue|Ave|Lane|Ln|Nagar|Colony|Sector)\b"

SCORES = {
    "emails": 8,
    "phones": 9,
    "addresses": 10,
    "aadhaar": 10,
    "pan": 10
}

COMMON_GPE = {"india","hyderabad","mumbai","bangalore","delhi","chennai"}

def remove_emojis(text: str) -> str:
    return re.sub(r"[\U0001F600-\U0001F64F]+", "", text)

def clean_text(text: str) -> str:
    text = remove_emojis(text)
    text = re.sub(r"http\S+|www\S+", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()

def tokenize_text(text: str) -> List[str]:
    tokens = re.findall(r"\b\w+\b", text.lower())
    return [t for t in tokens if t not in STOPWORDS]

def scrape_website_text(url: str) -> str:
    response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return soup.get_text(separator=" ").strip()

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
            if ent.text.lower() not in COMMON_GPE:
                gpes.add(ent.text)
        elif ent.label_ == "DATE":
            dates.add(ent.text)
    return {
        "PERSON": list(persons),
        "ORG": list(orgs),
        "GPE": list(gpes),
        "DATE": list(dates),
    }

def calculate_risk_score(detected: Dict[str, Any]) -> Dict[str, Any]:
    score = 0
    for key in ["emails", "phones", "addresses", "aadhaar", "pan"]:
        score += SCORES.get(key, 0) * len(detected["regex"].get(key, []))
    score += 0.5 * len(detected["ner"].get("GPE", []))
    score += 0.5 * len(detected["ner"].get("DATE", []))
    score += 0.3 * len(detected["ner"].get("ORG", []))
    score = min(score, 100)
    if score <= 20:
        level = "Low"
    elif score <= 50:
        level = "Medium"
    else:
        level = "High"
    return {"score": int(score), "level": level}

def generate_recommendations(detected: Dict[str, Any], risk_level: str) -> List[str]:
    recs = []
    if detected["regex"]["emails"]:
        recs.append("Remove or hide email addresses.")
    if detected["regex"]["phones"]:
        recs.append("Avoid sharing phone numbers publicly.")
    if detected["regex"]["addresses"]:
        recs.append("Remove physical address details.")
    if detected["regex"]["aadhaar"] or detected["regex"]["pan"]:
        recs.append("Remove Aadhaar/PAN immediately.")
    if risk_level == "High":
        recs.append("Restrict visibility and clean old posts.")
    if not recs:
        recs.append("No major risks detected.")
    return recs

def create_pdf_report(audit_id: str, report_data: Dict[str, Any]) -> str:
    filepath = os.path.join(REPORT_DIR, f"{audit_id}.pdf")
    doc = SimpleDocTemplate(filepath)
    styles = getSampleStyleSheet()
    content = []
    content.append(Paragraph("Privacy Audit Report", styles['Title']))
    content.append(Spacer(1, 10))
    content.append(Paragraph(f"Risk Score: {report_data['risk']['score']} ({report_data['risk']['level']})", styles['Normal']))
    content.append(Spacer(1, 10))
    for rec in report_data["recommendations"]:
        content.append(Paragraph(f"- {rec}", styles['Normal']))
        content.append(Spacer(1, 5))
    doc.build(content)
    return filepath

class AuditRequest(BaseModel):
    url: Optional[str] = None
    text: Optional[str] = None

@app.post("/audit")
def audit(payload: AuditRequest):
    if payload.url:
        raw = scrape_website_text(payload.url)
    elif payload.text:
        raw = payload.text
    else:
        raise HTTPException(status_code=400, detail="Provide url or text")
    cleaned = clean_text(raw)
    detected = {
        "regex": detect_regex_pii(cleaned),
        "ner": detect_ner(cleaned)
    }
    risk = calculate_risk_score(detected)
    recs = generate_recommendations(detected, risk["level"])
    audit_id = str(uuid.uuid4())
    data = {
        "_id": audit_id,
        "timestamp": str(datetime.datetime.now()),
        "detected": detected,
        "risk": risk,
        "recommendations": recs
    }
    audits.insert_one(data)
    return {"audit_id": audit_id, "risk": risk, "detected": detected, "recommendations": recs}

@app.post("/audit/upload")
async def upload(file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8", errors="ignore")
    return audit(AuditRequest(text=text))

@app.get("/audit")
def list_audits():
    return {"audits": list(audits.find({}, {"_id":1,"timestamp":1,"risk":1}))}

@app.get("/audit/{audit_id}")
def get_audit(audit_id: str):
    result = audits.find_one({"_id": audit_id})
    if not result:
        raise HTTPException(status_code=404, detail="Not found")
    return result

@app.delete("/audit/{audit_id}")
def delete(audit_id: str):
    audits.delete_one({"_id": audit_id})
    return {"message": "deleted"}

@app.get("/audit/{audit_id}/report")
def report(audit_id: str):
    audit = audits.find_one({"_id": audit_id})
    if not audit:
        raise HTTPException(status_code=404, detail="Not found")
    path = os.path.join(REPORT_DIR, f"{audit_id}.pdf")
    if not os.path.exists(path):
        create_pdf_report(audit_id, audit)
    return FileResponse(path, media_type="application/pdf")