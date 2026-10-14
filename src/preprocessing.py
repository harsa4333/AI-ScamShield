import re, html, base64, unicodedata
import numpy as np
import pandas as pd
import nltk
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer

try:
    _STOP = set(stopwords.words('english'))
except LookupError:
    nltk.download('stopwords')
    _STOP = set(stopwords.words('english'))
_STOP |= {'hou', 'ect', 'enron', 'nbsp'}
_STEMMER = PorterStemmer()

# ---------- decoding (base64 and quoted-printable emails) ----------
_SAFE_QP = re.compile(r'=([2-7][0-9A-F])')
_WS_QP = re.compile(r'=(0[9AD])')
_ALL_QP = re.compile(r'=([0-9A-F]{2})')
_LEAD_B64 = re.compile(r'^\s*[A-Za-z0-9+/\s]{80,}={0,2}')

def _try_b64(text):
    s = str(text)
    if ' ' in s.lstrip()[:60]:
        return s
    m = _LEAD_B64.match(s)
    if not m:
        return s
    raw = re.sub(r'[^A-Za-z0-9+/]', '', m.group(0))
    raw = raw[: len(raw) - (len(raw) % 4)]
    try:
        out = base64.b64decode(raw).decode('utf-8', errors='ignore')
    except Exception:
        return s
    printable = sum(c.isprintable() or c in '\r\n\t' for c in out) / max(len(out), 1)
    return (out + ' ' + s[m.end():]) if printable > 0.95 and len(out) > 20 else s

def decode_text(text):
    text = _try_b64(text)
    if len(_SAFE_QP.findall(text)) >= 3:
        text = re.sub(r'=\r?\n', '', text)
        text = _SAFE_QP.sub(lambda m: chr(int(m.group(1), 16)), text)
    text = _WS_QP.sub(' ', text)
    if len(_ALL_QP.findall(text)) >= 3:
        text = _ALL_QP.sub(lambda m: chr(int(m.group(1), 16)), text)
    text = unicodedata.normalize('NFKD', text)
    return ''.join(c for c in text if not unicodedata.combining(c))

# ---------- text cleaning for TF-IDF ----------
def preprocess_text(text):
    text = str(text).lower()
    text = html.unescape(text)
    text = re.sub(r'<.*?>', ' ', text)
    text = re.sub(r'http\S+|www\S+', ' ', text)
    text = re.sub(r'\S+@\S+', ' ', text)
    text = re.sub(r'[^a-z\s]', ' ', text)
    words = [w for w in text.split() if w not in _STOP and len(w) > 2]
    return ' '.join(_STEMMER.stem(w) for w in words)

# ---------- hand-made features ----------
def _rx(words):
    return re.compile(r'\b(?:' + '|'.join(re.escape(w) for w in words) + r')\b')

_URGENCY = _rx(['urgent', 'immediately', 'act now', 'hurry', 'asap', 'expire', 'expires',
                'expired', 'expiring', 'limited time', 'last chance', 'final notice',
                'final warning', 'deadline', 'today only'])
_AUTHORITY = _rx(['police', 'cbi', 'income tax', 'court', 'legal action', 'government',
                  'customs', 'bank official', 'rbi', 'arrest warrant', 'officer',
                  'department', 'federal', 'irs'])
_FINANCIAL = _rx(['transfer', 'wire', 'payment', 'pay now', 'bank account', 'account number',
                  'deposit', 'refund', 'fee', 'processing fee', 'claim your', 'send money',
                  'western union'])
_CREDENTIAL = _rx(['enter your otp', 'share your otp', 'verify your account',
                   'confirm your identity', 'enter your pin', 'enter your password',
                   'cvv', 'card number', 'security code', 'social security number', 'ssn'])
_URL = re.compile(r'http\S+|www\.\S+|\bbit\.ly/\S+|\bt\.me/\S+')
_PHONE = re.compile(r'\b\d{10,}\b|\+\d{1,3}[\s-]?\d{6,}')
_EMAIL = re.compile(r'\S+@\S+\.\S+')

def extract_features(text):
    t = str(text)
    low = t.lower()
    return {
        'message_length': len(t),
        'word_count': len(t.split()),
        'exclamation_count': t.count('!'),
        'caps_word_count': sum(1 for w in t.split() if w.isupper() and len(w) > 2),
        'has_urgency': int(bool(_URGENCY.search(low))),
        'has_authority_claim': int(bool(_AUTHORITY.search(low))),
        'has_financial_request': int(bool(_FINANCIAL.search(low))),
        'has_credential_request': int(bool(_CREDENTIAL.search(low))),
        'has_url': int(bool(_URL.search(t))),
        'has_phone_number': int(bool(_PHONE.search(t))),
        'has_email': int(bool(_EMAIL.search(t))),
    }

def features_df(series):
    return pd.DataFrame([extract_features(t) for t in series], index=series.index)
