# AI ScamShield

An early-warning system for suspicious messages. It reads an SMS, WhatsApp message, email or job offer and shows: a risk level, the scam types it resembles, the warning signs found (with the exact words), and safe next steps.

It gives a risk estimate, not a verdict. It does not prove that a message is a scam or that it is safe, and it does not replace banks, the police or your own judgement.

## What is in the project

- **Binary model:** logistic regression on TF-IDF text features and 11 engineered features. Test split: scam recall 0.94, precision 0.87, ROC-AUC 0.988 (threshold 0.40).
- **Scam-type model:** eight types (phishing, advance_fee, job_scam, lottery, digital_arrest, banking_kyc, upi_payment, investment).
- **Warning-sign layer:** ten rule-based checks (urgency, threats, authority claims, secrecy, OTP/PIN requests, payment requests, prize bait, guaranteed returns, UPI tricks, suspicious links).
- **Streamlit app** and a **four-page Power BI dashboard**.

## Folder structure

```
app/            Streamlit app (app.py)
src/            preprocessing.py, explain.py, scamshield.py
models/         binary_pipeline.joblib, scamtype_pipeline.joblib
notebooks/      numbered notebooks (cleaning, EDA, features, labels, modelling, evaluation, final pipeline)
notebooks/figures/   saved plots
data/raw/       original downloaded datasets (not included in the submission)
data/processed/ final_dataset.csv, challenge_set.csv, synthetic_scam.csv, synthetic_legit.csv
powerbi/        CSV files for the dashboard and AI_ScamShield.pbix
report_assets/  screenshots used in the report
```

## How to run the app

```
pip install -r requirements.txt
streamlit run app/app.py
```

Run it from the main project folder. The trained models must be in the `models/` folder. If they are missing, re-run the notebooks in order; `06_final_pipeline.ipynb` builds the final models.

## Data

Four public datasets were used: an SMS spam collection, a phishing email dataset, a fraud (advance-fee) email dataset and a fake job postings dataset. They are not redistributed here. Messages for digital-arrest, banking-KYC, UPI and investment scams, and Indian-style legitimate messages, were written by the project team because public data does not cover them. These rows are marked as synthetic in the `source` column.

## Results and limitations (summary)

| Model | Test split | Fresh challenge set |
|---|---|---|
| Binary (legit vs scam) | recall 0.94, precision 0.87 | 41 of 48 scams flagged; 5 of 12 hard legit messages flagged |
| Scam type | accuracy 0.96 | 30 of 48 correct type |

- Fake job postings are caught at only about 57%.
- The four Indian scam types were learned from synthetic messages only, so real-world accuracy is unknown.
- Genuine messages that mention KYC or RBI are sometimes flagged.
- The rule layer is mostly English-based.
- The system does not check links or phone numbers against live databases.

If you have lost money to fraud in India, call 1930 or report at cybercrime.gov.in.

Author: Harshvardhan Kumar, B.Tech CSE (Data Science and Analytics)