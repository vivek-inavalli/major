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
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

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
    
    # Count PII detections
    email_count = len(detected["regex"].get("emails", []))
    phone_count = len(detected["regex"].get("phones", []))
    address_count = len(detected["regex"].get("addresses", []))
    aadhaar_count = len(detected["regex"].get("aadhaar", []))
    pan_count = len(detected["regex"].get("pan", []))
    gpe_count = len(detected["ner"].get("GPE", []))
    date_count = len(detected["ner"].get("DATE", []))
    org_count = len(detected["ner"].get("ORG", []))
    
    # Critical PII (should block deployment)
    if aadhaar_count > 0 or pan_count > 0:
        return {"score": 100, "level": "High"}
    
    # Calculate weighted score
    if address_count > 0:
        score += 40
    if phone_count > 0:
        score += 35
    if email_count > 0:
        score += 20
    if gpe_count > 2:
        score += 15
    if date_count > 0:
        score += 5
    if org_count > 0:
        score += 5
    
    score = min(score, 99)  # Cap at 99 for High risk (not 100)
    
    if score == 0:
        level = "Low"
    elif score <= 20:
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
    doc = SimpleDocTemplate(filepath, topMargin=0.75*inch, bottomMargin=0.75*inch)
    styles = getSampleStyleSheet()
    
    # Create custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=12,
        alignment=TA_CENTER
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=10,
        spaceBefore=12,
        borderColor=colors.HexColor('#e0e0e0'),
        borderPadding=5
    )
    
    content = []
    
    # Header
    content.append(Paragraph("Privacy & Security Audit Report", title_style))
    content.append(Spacer(1, 12))
    
    # Audit Metadata
    metadata = [
        ["Audit ID:", audit_id],
        ["Generated:", report_data.get('timestamp', 'N/A')],
        ["Risk Level:", f"<b>{report_data['risk']['level']}</b>"],
        ["Risk Score:", f"<b>{report_data['risk']['score']}/100</b>"]
    ]
    
    metadata_table = Table(metadata, colWidths=[1.5*inch, 4*inch])
    metadata_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f5f5')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
    ]))
    content.append(metadata_table)
    content.append(Spacer(1, 20))
    
    # Risk Assessment Section
    content.append(Paragraph("Risk Assessment", heading_style))
    
    risk_level = report_data['risk']['level']
    risk_color = {
        'Low': '#27ae60',
        'Medium': '#f39c12',
        'High': '#e74c3c'
    }.get(risk_level, '#95a5a6')
    
    risk_text = f"<font color='{risk_color}'><b>RISK LEVEL: {risk_level}</b></font><br/>"
    risk_text += f"Risk Score: {report_data['risk']['score']}/100<br/>"
    
    if risk_level == 'Low':
        risk_text += "Your content meets privacy standards with minimal PII exposure."
    elif risk_level == 'Medium':
        risk_text += "Your content contains sensitive information that should be reviewed and remediated."
    else:
        risk_text += "Your content contains critical PII that must be removed immediately before deployment."
    
    content.append(Paragraph(risk_text, styles['Normal']))
    content.append(Spacer(1, 15))
    
    # Detailed Findings Section
    content.append(Paragraph("Detailed Findings", heading_style))
    
    detected = report_data.get('detected', {})
    findings_data = []
    
    # Regex-based PII
    regex_pii = detected.get('regex', {})
    
    if regex_pii.get('emails'):
        findings_data.append(['Emails Found', str(len(regex_pii['emails']))])
    if regex_pii.get('phones'):
        findings_data.append(['Phone Numbers', str(len(regex_pii['phones']))])
    if regex_pii.get('addresses'):
        findings_data.append(['Physical Addresses', str(len(regex_pii['addresses']))])
    if regex_pii.get('aadhaar'):
        findings_data.append(['Aadhaar Numbers (CRITICAL)', str(len(regex_pii['aadhaar']))])
    if regex_pii.get('pan'):
        findings_data.append(['PAN Numbers (CRITICAL)', str(len(regex_pii['pan']))])
    
    # NER-based entities
    ner_entities = detected.get('ner', {})
    
    if ner_entities.get('PERSON'):
        findings_data.append(['Person Names', str(len(ner_entities['PERSON']))])
    if ner_entities.get('ORG'):
        findings_data.append(['Organizations', str(len(ner_entities['ORG']))])
    if ner_entities.get('GPE'):
        findings_data.append(['Geographic Locations', str(len(ner_entities['GPE']))])
    if ner_entities.get('DATE'):
        findings_data.append(['Dates/Timestamps', str(len(ner_entities['DATE']))])
    
    if findings_data:
        findings_table = Table(findings_data, colWidths=[3*inch, 2*inch])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#bdc3c7')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#ecf0f1')]),
        ]))
        content.append(findings_table)
    else:
        content.append(Paragraph("No PII or sensitive data detected.", styles['Normal']))
    
    content.append(Spacer(1, 20))
    
    # Detailed PII Details (if any found)
    has_pii = any([
        regex_pii.get(key) for key in ['emails', 'phones', 'addresses', 'aadhaar', 'pan']
    ]) or any([
        ner_entities.get(key) for key in ['PERSON', 'ORG', 'GPE', 'DATE']
    ])
    
    if has_pii:
        content.append(Paragraph("PII Details", heading_style))
        
        if regex_pii.get('emails'):
            content.append(Paragraph(f"<b>Emails:</b> {', '.join(regex_pii['emails'][:10])}", styles['Normal']))
            if len(regex_pii['emails']) > 10:
                content.append(Paragraph(f"... and {len(regex_pii['emails']) - 10} more", styles['Normal']))
            content.append(Spacer(1, 8))
        
        if regex_pii.get('phones'):
            content.append(Paragraph(f"<b>Phone Numbers:</b> {', '.join(regex_pii['phones'][:10])}", styles['Normal']))
            if len(regex_pii['phones']) > 10:
                content.append(Paragraph(f"... and {len(regex_pii['phones']) - 10} more", styles['Normal']))
            content.append(Spacer(1, 8))
        
        if regex_pii.get('addresses'):
            content.append(Paragraph(f"<b>Addresses:</b> {regex_pii['addresses'][0][:80] if regex_pii['addresses'] else 'N/A'}", styles['Normal']))
            if len(regex_pii['addresses']) > 1:
                content.append(Paragraph(f"... and {len(regex_pii['addresses']) - 1} more", styles['Normal']))
            content.append(Spacer(1, 8))
        
        if regex_pii.get('aadhaar'):
            content.append(Paragraph("<b style='color: #e74c3c'>Aadhaar Numbers (CRITICAL):</b> Found and must be removed immediately", styles['Normal']))
            content.append(Spacer(1, 8))
        
        if regex_pii.get('pan'):
            content.append(Paragraph("<b style='color: #e74c3c'>PAN Numbers (CRITICAL):</b> Found and must be removed immediately", styles['Normal']))
            content.append(Spacer(1, 8))
        
        if ner_entities.get('PERSON'):
            names = ner_entities['PERSON'][:10]
            content.append(Paragraph(f"<b>Person Names:</b> {', '.join(names)}", styles['Normal']))
            if len(ner_entities['PERSON']) > 10:
                content.append(Paragraph(f"... and {len(ner_entities['PERSON']) - 10} more", styles['Normal']))
            content.append(Spacer(1, 8))
        
        content.append(PageBreak())
    
    # Recommendations Section
    content.append(Paragraph("Recommendations", heading_style))
    
    for i, rec in enumerate(report_data.get("recommendations", []), 1):
        content.append(Paragraph(f"{i}. {rec}", styles['Normal']))
        content.append(Spacer(1, 8))
    
    content.append(Spacer(1, 20))
    
    # Footer
    content.append(Paragraph("<hr/>", styles['Normal']))
    footer_text = f"Report Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
    footer_text += "This report is confidential and for authorized use only."
    content.append(Paragraph(footer_text, styles['Normal']))
    
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

@app.post("/audit/{audit_id}/ship")
def ship_audit(audit_id: str):
    """Validate audit before shipping to production."""
    audit = audits.find_one({"_id": audit_id})
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    
    risk_level = audit["risk"]["level"]
    risk_score = audit["risk"]["score"]
    
    # Only allow shipping Low-risk audits
    if risk_level == "Low":
        return {
            "status": "approved",
            "message": "Audit passed security check. Safe to ship.",
            "risk_score": risk_score,
            "risk_level": risk_level
        }
    elif risk_level == "Medium":
        raise HTTPException(
            status_code=403,
            detail=f"Cannot ship: Medium risk detected (score: {risk_score}). Please review and remediate issues."
        )
    else:  # High
        raise HTTPException(
            status_code=403,
            detail=f"Cannot ship: High risk detected (score: {risk_score}). Critical PII found. Please remove sensitive data."
        )
