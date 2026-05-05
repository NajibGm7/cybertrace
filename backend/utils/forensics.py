"""
CyberTrace - File Analysis Engine
Handles hash generation, file type detection, metadata extraction,
and rule-based suspicious-file / basic malware detection.
"""

import hashlib
import os
import json
import mimetypes
from datetime import datetime

# ── Optional heavy deps (graceful fallback if not installed) ─────────────────
try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import PyPDF2
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    from docx import Document as DocxDocument
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False

try:
    import magic
    MAGIC_AVAILABLE = True
except Exception:
    MAGIC_AVAILABLE = False


# ── Suspicious File Rules ────────────────────────────────────────────────────

SUSPICIOUS_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.js',
    '.jar', '.msi', '.dll', '.ps1', '.sh', '.bin', '.run', '.elf',
    '.hta', '.wsf', '.reg', '.lnk'
}

# Simple byte-pattern signatures (offset, bytes) – educational examples
MALWARE_SIGNATURES = [
    (0,  b'MZ',          'Windows PE Executable (EXE/DLL)'),
    (0,  b'\x7fELF',     'Linux ELF Executable'),
    (0,  b'PK\x03\x04',  'ZIP archive (could be JAR/DOCM/XLSM)'),
    (0,  b'\xd0\xcf\x11\xe0', 'Legacy MS Office / Compound Document'),
]

SUSPICIOUS_STRINGS = [
    b'cmd.exe', b'powershell', b'WScript.Shell',
    b'eval(', b'base64_decode', b'CreateObject',
    b'HKEY_LOCAL_MACHINE', b'RegCreateKey',
    b'socket.connect', b'urllib.request',
]


# ── Hash Generation ──────────────────────────────────────────────────────────

def generate_hashes(filepath: str) -> dict:
    """Compute MD5, SHA-1, SHA-256 for a file. Returns dict of hashes."""
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        'md5':    md5.hexdigest(),
        'sha1':   sha1.hexdigest(),
        'sha256': sha256.hexdigest(),
    }


# ── MIME / File Type Detection ───────────────────────────────────────────────

def detect_mime(filepath: str, filename: str) -> str:
    """Detect MIME type using python-magic if available, else mimetypes."""
    if MAGIC_AVAILABLE:
        try:
            return magic.from_file(filepath, mime=True)
        except Exception:
            pass
    mime, _ = mimetypes.guess_type(filename)
    return mime or 'application/octet-stream'


# ── Suspicious / Malware Detection ──────────────────────────────────────────

def scan_file(filepath: str, filename: str) -> dict:
    """
    Rule-based scan of a file.
    Returns: {is_suspicious, risk_level, findings, signature_matches}
    """
    findings = []
    signature_matches = []
    ext = os.path.splitext(filename)[1].lower()

    # 1. Extension check
    if ext in SUSPICIOUS_EXTENSIONS:
        findings.append(f'Suspicious extension detected: {ext}')

    # 2. Byte signature scan (first 8 KB)
    try:
        with open(filepath, 'rb') as f:
            header = f.read(8192)

        for offset, sig, label in MALWARE_SIGNATURES:
            if header[offset:offset+len(sig)] == sig:
                signature_matches.append(label)

        # 3. Suspicious string scan
        for s in SUSPICIOUS_STRINGS:
            if s in header:
                findings.append(f'Suspicious string found: {s.decode("utf-8", errors="replace")}')

    except Exception as e:
        findings.append(f'Read error during scan: {e}')

    # 4. Hidden file check (Unix-style dot files)
    if os.path.basename(filename).startswith('.'):
        findings.append('Hidden file (dot-prefixed filename)')

    # 5. Extension-MIME mismatch (simple)
    mime = detect_mime(filepath, filename)
    if ext in ('.jpg', '.jpeg', '.png', '.gif') and 'image' not in mime:
        findings.append(f'Extension/MIME mismatch: ext={ext}, mime={mime}')

    # Risk level
    total = len(findings) + len(signature_matches)
    if total == 0:
        risk = 'clean'
    elif total <= 2:
        risk = 'low'
    elif total <= 4:
        risk = 'medium'
    else:
        risk = 'high'

    return {
        'is_suspicious':     total > 0,
        'risk_level':        risk,
        'findings':          findings,
        'signature_matches': signature_matches,
        'scanned_at':        datetime.utcnow().isoformat()
    }


# ── Metadata Extraction ──────────────────────────────────────────────────────

def extract_metadata(filepath: str, filename: str) -> dict:
    """
    Extract file metadata based on type.
    Returns a dict of findings.
    """
    meta = {
        'filename':   filename,
        'size_bytes': os.path.getsize(filepath),
        'mime_type':  detect_mime(filepath, filename),
        'extension':  os.path.splitext(filename)[1].lower(),
    }
    ext = meta['extension']

    # Image metadata (EXIF)
    if ext in ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff') and PIL_AVAILABLE:
        try:
            img = Image.open(filepath)
            meta['image_format'] = img.format
            meta['image_size']   = f'{img.width}x{img.height}'
            meta['image_mode']   = img.mode
            exif_raw = img._getexif() if hasattr(img, '_getexif') else None
            if exif_raw:
                exif = {TAGS.get(k, k): str(v) for k, v in exif_raw.items()
                        if TAGS.get(k, k) not in ('MakerNote', 'UserComment')}
                meta['exif'] = exif
        except Exception as e:
            meta['image_error'] = str(e)

    # PDF metadata
    elif ext == '.pdf' and PDF_AVAILABLE:
        try:
            with open(filepath, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                info = reader.metadata or {}
                meta['pdf_pages']  = len(reader.pages)
                meta['pdf_author'] = str(info.get('/Author', 'Unknown'))
                meta['pdf_title']  = str(info.get('/Title', 'Unknown'))
                meta['pdf_creator']= str(info.get('/Creator', 'Unknown'))
                meta['pdf_encrypted'] = reader.is_encrypted
        except Exception as e:
            meta['pdf_error'] = str(e)

    # DOCX metadata
    elif ext == '.docx' and DOCX_AVAILABLE:
        try:
            doc  = DocxDocument(filepath)
            core = doc.core_properties
            meta['docx_author']   = core.author or 'Unknown'
            meta['docx_title']    = core.title  or 'Unknown'
            meta['docx_created']  = str(core.created)
            meta['docx_modified'] = str(core.modified)
            meta['docx_paragraphs'] = len(doc.paragraphs)
        except Exception as e:
            meta['docx_error'] = str(e)

    return meta
