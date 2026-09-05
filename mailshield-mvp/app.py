"""
app.py — MailShield MVP

Single-page Streamlit dashboard for SIH26106 demo. Pick a sample email or
upload a custom .eml, and see the full forensic pipeline run end-to-end:
header forensics -> ML/NLP classification -> geolocation -> fusion score.

Run with: streamlit run app.py
"""

import os
import glob
import datetime
import streamlit as st
import folium
from streamlit_folium import st_folium
from fpdf import FPDF

from core.header_forensics import analyze_raw
from core.scorer import header_risk_score
from core.classifier import predict as ml_predict
from core.geo_lookup import get_geo
from core.fusion import compute_fraud_score

st.set_page_config(page_title="MailShield — SIH26106", page_icon="🛡️", layout="wide")

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "data", "sample_emails")


@st.cache_data(show_spinner=False)
def run_pipeline(raw_content: str) -> dict:
    """Runs the full analysis pipeline on raw .eml text. Cached by content."""
    forensics = analyze_raw(raw_content)
    h_score = header_risk_score(forensics)
    ml_result = ml_predict(forensics["subject"] + " " + forensics["body_text"])
    geo = get_geo(forensics["earliest_external_ip"])
    fusion = compute_fraud_score(h_score["score"], ml_result, geo)
    return {
        "forensics": forensics,
        "header_score": h_score,
        "ml_result": ml_result,
        "geo": geo,
        "fusion": fusion,
    }


def generate_pdf_report(result: dict, case_id: str) -> bytes:
    forensics = result["forensics"]
    fusion = result["fusion"]

    def heading(pdf_obj, text, size=11):
        pdf_obj.set_x(pdf_obj.l_margin)
        pdf_obj.set_font("Helvetica", "B", size)
        pdf_obj.multi_cell(0, 8, text)
        pdf_obj.set_font("Helvetica", "", 10)

    def body(pdf_obj, text):
        pdf_obj.set_x(pdf_obj.l_margin)
        pdf_obj.multi_cell(0, 6, text)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    heading(pdf, "MailShield Forensic Report", size=16)
    body(pdf, f"Case ID: {case_id}\nGenerated: {datetime.datetime.now().isoformat()}")
    pdf.ln(3)

    heading(pdf, f"Final Fraud Score: {fusion['final_score']}/100 - {fusion['verdict']}", size=12)
    pdf.ln(2)

    heading(pdf, "Email Details")
    body(pdf, f"Subject: {forensics['subject']}\n"
              f"From: {forensics['from_addr']}\n"
              f"Message-ID: {forensics['message_id']}\n"
              f"Date: {forensics['date']}")
    pdf.ln(2)

    heading(pdf, "Header Authentication")
    body(pdf, f"SPF: {forensics['spf']}   DKIM: {forensics['dkim']}   DMARC: {forensics['dmarc']}")
    if forensics["anomalies"]:
        anomaly_text = "Anomalies detected:\n" + "\n".join(f"- {a}" for a in forensics["anomalies"])
        body(pdf, anomaly_text)
    pdf.ln(2)

    heading(pdf, "Origin Traceability")
    geo = result["geo"]
    body(pdf, f"Earliest external IP: {forensics['earliest_external_ip'] or 'Not found (internal routing only)'}\n"
              f"Location: {geo['city']}, {geo['country']}\n"
              f"ISP/Infrastructure: {geo['isp']}\n"
              f"Hosting/VPN flagged: {geo['is_hosting_or_vpn']}")
    pdf.ln(2)

    heading(pdf, "Score Breakdown")
    b = fusion["breakdown"]
    body(pdf, f"NLP/ML contribution: {b['ml_contribution']}\n"
              f"Header forensics contribution: {b['header_contribution']}\n"
              f"Geo/infrastructure contribution: {b['geo_contribution']}")

    return bytes(pdf.output(dest="S"))


# ---------------- Sidebar ----------------
st.sidebar.title("🛡️ MailShield")
st.sidebar.caption("SIH26106 — AI-Powered Email Threat Detection & Forensic Intelligence")
st.sidebar.markdown("---")
st.sidebar.success("Demo Mode: offline-safe (geo lookups fall back automatically)")

sample_files = sorted(glob.glob(os.path.join(SAMPLE_DIR, "*.eml")))
sample_names = [os.path.basename(p) for p in sample_files]

source_mode = st.sidebar.radio("Email source", ["Sample email", "Upload .eml"])

raw_content = None
display_name = None

if source_mode == "Sample email":
    chosen = st.sidebar.selectbox("Choose a sample", sample_names)
    with open(os.path.join(SAMPLE_DIR, chosen), "r", encoding="utf-8", errors="replace") as f:
        raw_content = f.read()
    display_name = chosen
else:
    uploaded = st.sidebar.file_uploader("Upload an .eml file", type=["eml"])
    if uploaded is not None:
        raw_content = uploaded.read().decode("utf-8", errors="replace")
        display_name = uploaded.name

if raw_content is None:
    st.title("MailShield")
    st.info("Select a sample email or upload an .eml file from the sidebar to begin analysis.")
    st.stop()

result = run_pipeline(raw_content)
forensics = result["forensics"]
fusion = result["fusion"]

# ---------------- Main layout ----------------
st.title("MailShield — Email Forensic Analysis")
st.caption(f"Analyzing: **{display_name}**")

score = fusion["final_score"]
verdict = fusion["verdict"]
color = "🟢" if score < 30 else "🟡" if score < 70 else "🔴"

col1, col2 = st.columns([1, 1.3])

with col1:
    st.subheader("Email Details")
    st.markdown(f"**Subject:** {forensics['subject']}")
    st.markdown(f"**From:** {forensics['from_addr']}")
    st.markdown(f"**Date:** {forensics['date']}")
    with st.expander("Body preview", expanded=False):
        st.text(forensics["body_text"][:1000])

    st.markdown("---")
    st.metric(label=f"{color} Fraud Score", value=f"{score} / 100", delta=verdict, delta_color="off")

    case_id = f"MSH-{abs(hash(display_name)) % 100000:05d}"
    st.caption(f"Case ID: {case_id}")

    pdf_bytes = generate_pdf_report(result, case_id)
    st.download_button(
        "📄 Generate Forensic Report (PDF)",
        data=pdf_bytes,
        file_name=f"{case_id}_forensic_report.pdf",
        mime="application/pdf",
    )

with col2:
    with st.expander("🔍 Header Forensics (SPF / DKIM / DMARC)", expanded=True):
        c1, c2, c3 = st.columns(3)
        c1.metric("SPF", forensics["spf"].upper())
        c2.metric("DKIM", forensics["dkim"].upper())
        c3.metric("DMARC", forensics["dmarc"].upper())
        if forensics["anomalies"]:
            st.warning("Anomalies detected:")
            for a in forensics["anomalies"]:
                st.markdown(f"- {a}")
        else:
            st.success("No header anomalies detected.")

    with st.expander("🧠 NLP/ML Content Analysis", expanded=True):
        ml = result["ml_result"]
        st.markdown(f"**Label:** {ml['label']}  |  **Confidence:** {ml['confidence']}%")
        if ml["top_words"]:
            st.markdown(f"**Top influencing terms:** {', '.join(ml['top_words'])}")

    with st.expander("🌍 Origin Traceability & Geolocation", expanded=True):
        geo = result["geo"]
        ip = forensics["earliest_external_ip"]
        if ip:
            st.markdown(f"**Earliest external IP:** `{ip}`")
            st.markdown(f"**Location:** {geo['city']}, {geo['country']}")
            st.markdown(f"**ISP/Infrastructure:** {geo['isp']}")
            if geo["is_hosting_or_vpn"]:
                st.warning("⚠️ Flagged as hosting/VPN/datacenter infrastructure — not a typical residential sender.")
            st.caption("Note: geolocation is approximate and based on IP registration data.")

            m = folium.Map(location=[geo["lat"], geo["lon"]], zoom_start=4)
            folium.Marker(
                [geo["lat"], geo["lon"]],
                popup=f"{ip} — {geo['city']}, {geo['country']}",
                icon=folium.Icon(color="red" if geo["is_hosting_or_vpn"] else "blue"),
            ).add_to(m)
            st_folium(m, width=None, height=300)
        else:
            st.info("No external IP found in the routing chain — email likely originated from internal/trusted infrastructure.")

    with st.expander("📊 Score Breakdown", expanded=True):
        b = fusion["breakdown"]
        st.bar_chart({
            "Contribution": {
                "ML/NLP (40%)": b["ml_contribution"],
                "Header Forensics (35%)": b["header_contribution"],
                "Geo/Infra (25%)": b["geo_contribution"],
            }
        })
