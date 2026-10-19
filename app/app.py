import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

import streamlit as st
from scamshield import analyze, THRESHOLD

st.set_page_config(page_title="AI ScamShield", page_icon="🛡️", layout="centered")

COLORS = {'Low': '#2e7d32', 'Medium': '#f9a825', 'High': '#ef6c00', 'Very high': '#c62828'}
TYPE_NAMES = {
    'digital_arrest': 'Digital arrest / authority impersonation',
    'banking_kyc': 'Banking / KYC fraud',
    'upi_payment': 'UPI / payment scam',
    'investment': 'Investment scam',
    'phishing': 'Phishing',
    'advance_fee': 'Advance-fee ("419") scam',
    'job_scam': 'Job scam',
    'lottery': 'Lottery / prize scam',
}
SAMPLES = {
    "Fake inspector": "This is Inspector Rao from Mumbai Cyber Crime. A parcel in your name contains illegal items. Stay on this video call and do not tell anyone or you will be arrested.",
    "Fake KYC": "Dear customer, your HDFC KYC is expired. Update immediately at http://hdfc-kyc-update.in/login or your account will be blocked today.",
    "Tip group": "Join our VIP Telegram group: guaranteed 30% monthly returns, zero risk. Limited seats, deposit Rs 5000 today. t.me/vip_profit_club",
    "Bank alert": "SBI: Rs 450 debited from A/c ending 2231 on 05-Nov via UPI to Swiggy. Not you? Call 1800 112 211. Never share your OTP or PIN.",
    "Casual chat": "Hey are we still meeting for lunch tomorrow? Let me know.",
}

st.session_state.setdefault('msg', '')

st.title("🛡️ AI ScamShield")
st.caption("An early-warning tool. It estimates how suspicious a message looks. It cannot prove that a message is a scam or that it is safe.")

st.write("Try an example:")
cols = st.columns(len(SAMPLES))
for col, (label, text) in zip(cols, SAMPLES.items()):
    if col.button(label, use_container_width=True):
        st.session_state.msg = text

message = st.text_area("Paste a suspicious SMS, WhatsApp message, email or link:", key='msg', height=160)
check = st.button("Check message", type="primary")

if check:
    if not message.strip():
        st.warning("Please paste a message first.")
    else:
        r = analyze(message)
        color = COLORS[r['level']]
        st.markdown(
            f"<div style='padding:16px;border-radius:10px;background:{color};color:white;'>"
            f"<span style='font-size:14px'>Risk level</span><br>"
            f"<span style='font-size:32px;font-weight:700'>{r['level']}</span></div>",
            unsafe_allow_html=True)

        if r['score'] is not None:
            st.progress(min(max(r['score'], 0.0), 1.0))
            st.caption(f"Model score: {r['score']:.2f} (0 = looks normal, 1 = looks very much like known scams). "
                       f"Messages scoring {THRESHOLD:.2f} or more are flagged as likely scams.")
        if r['bumped_by_rules']:
            st.info("The model score was low, but the message contains strong warning signs, so the level was raised to Medium.")
        if r['note']:
            st.info(r['note'])

        shown = [(t, p) for t, p in r['types'] if p >= 0.20]
        if shown:
            st.subheader("What type of scam does it resemble?")
            for t, p in shown:
                st.write(f"**{TYPE_NAMES.get(t, t)}** ({p:.0%})")
                st.progress(min(max(p, 0.0), 1.0))
            st.caption("Scam types overlap in real life, so up to three are shown. This is a guess from the message wording.")

        if r['signals']:
            st.subheader("Warning signs found")
            for s in r['signals']:
                with st.expander(s['title'], expanded=True):
                    st.write(s['why'])
                    st.code(s['evidence'], language=None)
            st.caption("Warning signs are rule-based checks shown next to the score. They are not a breakdown of how the model calculated it.")
        elif r['score'] is not None:
            st.success("No common scam warning signs were found.")

        st.subheader("What to do next")
        for a in r['advice']:
            st.markdown(f"- {a}")
        if r['level'] == 'Low':
            st.caption("Low risk does not mean safe. If a message asks for money, OTPs or personal details, verify it independently.")

with st.sidebar:
    st.header("About")
    st.write("AI ScamShield scores messages with a machine-learning model, then adds rule-based checks for common scam tactics.")
    st.header("Limitations")
    st.write(
        "- It can be wrong in both directions: scams may look safe, and genuine messages (for example a real bank notice that mentions KYC) may look risky.\n"
        "- Scam-type labels for UPI, digital arrest, banking KYC and investment scams were learned mostly from messages we wrote ourselves.\n"
        "- It does not check links or phone numbers against any live database.\n"
        "- It is not a substitute for your bank, the police or your own judgement."
    )
    st.write("If you have lost money to fraud, call **1930** or report at cybercrime.gov.in.")
