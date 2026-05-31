import re
import email
from email.message import Message
from fastapi import APIRouter, UploadFile, File

router = APIRouter()

def sanitize_email(text: str) -> str:
    if not isinstance(text, str):
        return str(text) if text is not None else "Unknown"
    return text.encode("utf-8", errors="ignore").decode("utf-8")

def url_extracter(text: str) -> list:

    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    found_ip = re.findall(ip_pattern, text)

    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    found_urls = re.findall(url_pattern, text)

    safeurl = []
    for url in found_urls:
        nullified_url = url.replace("http", "hxxp").replace(".", "[.]")
        safeurl.append(nullified_url)

    return{
        "url": list(set(safeurl)), 
       "ip": list(found_ip)
       }


def email_text_extractor(email_content: Message) -> str:
    valid_types = ["text/plain", "text/html"]

    if not email_content.is_multipart():
        if email_content.get_content_type() in valid_types:
            return email_content.get_payload(decode=True).decode('utf-8', errors="replace")
        return ""
    
    extracted_text = ""

    for part in email_content.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition"))
        if content_type in valid_types and "attachment" not in content_disposition:
            try:
                extracted_text += part.get_payload(decode=True).decode('utf-8', errors='replace') +"\n"
                break
            except Exception as e:
                print(f"Failed to decode part: {e}")
    return extracted_text.strip()

@router.post("/api/email/parse")
async def parse_uploaded_email(file: UploadFile = File(...)):
    raw_bytes = await file.read()
    parsed_email = email.message_from_bytes(raw_bytes)

    sender = parsed_email.get("From")
    subject = parsed_email.get("Subject")
    date = parsed_email.get("Date")

    body_content = email_text_extractor(parsed_email)
    safe_links = url_extracter(body_content)

    return {
        "status": "success",
        "metadata": {
            "sender": sanitize_email(sender),
            "subject": sanitize_email(subject),
            "date": sanitize_email(date)
        },
        "indicators": {
            "defanged_urls" : safe_links['url'],
            "ip": safe_links['ip']
        },
        "preview": sanitize_email(body_content[:300])
        }