import re

I = re.I

SIGNALS = [
    dict(key='urgency', title='Pressure to act fast',
         why='Scammers rush you so you do not stop to think or check.',
         patterns=[re.compile(r"\b(urgent(ly)?|immediately|asap|hurry|final (notice|warning|reminder)|last chance|expir(es|ed|ing|y)|within \d+ ?(min(ute)?s?|hours?|hrs?)|before midnight|tonight|right now)\b", I)]),
    dict(key='threat', title='Threat of arrest, blocking or legal action',
         why='Threats are used to scare people into acting without thinking.',
         patterns=[re.compile(r"\b(arrest(ed)?|warrant|legal action|jail|fir|case (is )?(registered|filed)|blocked?|suspended?|frozen|freeze[sd]?|deactivated?|disconnected?|closure|seized|detained|detention|prosecut\w+)\b", I)]),
    dict(key='authority', title='Mentions or claims to be a government body, police or court',
         why='Scammers often pretend to be police, CBI, customs, TRAI, RBI or a court.',
         patterns=[re.compile(r"\b(cbi|enforcement directorate|narcotics|ncb|customs|trai|rbi|police|cyber ?(crime|cell|branch)|income tax|supreme court|high court|interpol|nia|(sub-?)?inspector)\b", I)]),
    dict(key='secrecy', title='Asks you to keep it secret or stay on the line',
         why='Real agencies and banks do not tell you to hide a matter from your family or keep a call open.',
         patterns=[re.compile(r"\b(do not|don't|dont|never|mat)\s+(tell|inform|share|discuss|contact)\b[^.]{0,25}\b(anyone|any one|anybody|nobody|family|parents|relatives|lawyer)\b", I),
                   re.compile(r"\bkeep (this|it|the matter)[^.]{0,15}(confidential|secret)\b|\bstrictly confidential\b|\bkeep this matter confidential\b", I),
                   re.compile(r"\b(do not|don't|dont|never)\s+(disconnect|hang up|cut)\b|\bstay on (the |this )?(call|video)\b|\bkeep (your )?(camera|video) on\b|\bphone mat kaat", I),
                   re.compile(r"\bkisi ko[^.]{0,20}(na|mat)\s+bata", I)]),
    dict(key='credential', title='Asks for an OTP, PIN, password or card details',
         why='A genuine bank or agency never asks you to share these.', negatable=True,
         patterns=[re.compile(r"\b(share|send|enter|tell|reply with|provide|submit|give|read out|dalein|bhejo|bhejein|batayein|bataiye)\b[^.]{0,40}\b(otp|upi pin|pin|cvv|password|card number|aadhaar|aadhar|pan)\b", I),
                   re.compile(r"\benter your (upi )?pin\b", I)]),
    dict(key='payment', title='Asks you to pay or transfer money',
         why='Being asked to pay a fee or move money to a "safe" or "verification" account is a classic scam step.',
         patterns=[re.compile(r"\b(pay|transfer|send|deposit)\b[^.]{0,40}\b(rs\.?|inr|usd|fee|amount|balance|money|funds|deposit)\b", I),
                   re.compile(r"\b(verification|processing|clearance|registration|joining) (fee|charge|amount)\b|\bsafe account\b|\bverification account\b", I)]),
    dict(key='prize', title='Prize, cashback or reward hook',
         why='You cannot win a prize you never entered. Rewards are used as bait.',
         patterns=[re.compile(r"\b(you (have )?(just )?won|winner|prize|lottery|jackpot|cashback|congratulations|scratch card|claim (your|ur|yr))\b", I)]),
    dict(key='returns', title='Promises of guaranteed or unusually high returns',
         why='No genuine investment guarantees profit or doubles your money quickly.',
         patterns=[re.compile(r"\b(guaranteed (returns?|profit)|double your (money|investment)|risk[- ]free|sure[- ]shot|no risk|100% safe|crypto(currency)?|forex|trading (group|bot|signals)|\d+ ?% (daily|weekly|monthly|returns?|profit))\b", I)]),
    dict(key='upi_trick', title='Asks you to approve a request or scan a code to receive money',
         why='You never need your PIN, a QR scan or a collect-request approval to receive money.',
         patterns=[re.compile(r"\b(collect request|scan (this|the)? ?qr|qr code|approve (the|this|pending)?[^.]{0,15}request)\b", I)]),
]

_URL = re.compile(
    r"(?:https?://|www\.)\S+"
    r"|\b(?:bit\.ly|tinyurl\.com|t\.me|wa\.me|goo\.gl|rb\.gy|cutt\.ly)/\S+"
    r"|\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*\.(?:com|in|net|org|co\.in|xyz|top|info|online|site|link|click|app)\b(?:/\S*)?",
    I)
_BAIT = re.compile(r"kyc|verify|secure|update|login|refund|claim|pay|reward|reverify|portal", I)
_NEGATIONS = ['do not', "don't", 'dont', 'never', 'not ', 'no one', 'nobody', 'kabhi nahi', ' mat ']

def _negated(text, start):
    before = text[max(0, start - 25):start].lower()
    return any(n in before for n in _NEGATIONS)

def _suspicious_link(text):
    for u in _URL.findall(text):
        host = re.sub(r"^(https?://)?(www\.)?", "", u, flags=I).split('/')[0].lower()
        shortener = host in ('bit.ly', 'tinyurl.com', 't.me', 'wa.me', 'goo.gl', 'rb.gy', 'cutt.ly')
        is_ip = bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(:\d+)?", host))
        spoof = '-' in host and bool(_BAIT.search(host))
        if shortener or is_ip or spoof:
            return u
    return None

def detect(text):
    text = str(text)
    found = []
    for s in SIGNALS:
        ev = None
        for p in s['patterns']:
            for m in p.finditer(text):
                if s.get('negatable') and _negated(text, m.start()):
                    continue
                ev = text[max(0, m.start() - 15): m.end() + 25].replace('\n', ' ').strip()
                break
            if ev:
                break
        if ev:
            found.append(dict(key=s['key'], title=s['title'], why=s['why'], evidence=ev))
    link = _suspicious_link(text)
    if link:
        found.append(dict(key='link', title='Suspicious link',
                          why='The link is shortened, an IP address, or a look-alike address that mixes bank-style words. Real banks use their own plain domains.',
                          evidence=link))
    return found

GENERAL = [
    "Never share your OTP, PIN, CVV or password with anyone, even someone claiming to be from a bank or police.",
    "Do not send money because of pressure or threats. Take time and talk to someone you trust first.",
    "Verify independently: use the phone number on your card, the official app or website (typed yourself), or visit the branch.",
    "If money is already lost, call 1930 or report at cybercrime.gov.in as soon as possible.",
]
BY_TYPE = {
    'digital_arrest': "Police, CBI, customs or courts do not arrest people over a video call or ask for money to a 'safe account'. Hang up, do not pay, and tell a family member.",
    'banking_kyc': "Banks do not ask you to complete KYC through a link, WhatsApp or by sharing an OTP. Update KYC only at the branch or in the official app.",
    'upi_payment': "You never need your UPI PIN, a QR scan or a collect-request approval to receive money. Do not approve requests you did not start.",
    'investment': "No investment can guarantee returns. Check that the adviser is registered on the SEBI website and do not join tip groups on Telegram or WhatsApp.",
    'phishing': "Do not click links, open attachments or call numbers given in the message. Contact the organisation using details you find yourself.",
    'advance_fee': "Strangers who offer you a share of a large sum are scammers. Never pay a fee to receive money.",
    'job_scam': "Genuine employers do not ask you to pay for a job, a kit or training. Check the company on its official website.",
    'lottery': "You cannot win a lottery you did not enter. Never pay a fee or share details to claim a prize.",
}
BY_SIGNAL = {
    'secrecy': "Being told to keep something secret is a red flag. Tell a family member or friend about this message right now.",
    'link': "Do not click the link. Type the official address yourself if you need to check something.",
    'urgency': "Pressure to act within minutes is a tactic. A real bank or agency will allow you time to verify.",
}

def advice_for(scam_types=(), signal_keys=(), max_items=6):
    out = []
    for t in scam_types:
        if t in BY_TYPE:
            out.append(BY_TYPE[t])
    for k in signal_keys:
        if k in BY_SIGNAL:
            out.append(BY_SIGNAL[k])
    out += GENERAL
    seen, final = set(), []
    for a in out:
        if a not in seen:
            seen.add(a)
            final.append(a)
    return final[:max_items]
