from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from preprocessing import decode_text, preprocess_text, features_df
import explain

_MODELS = Path(__file__).resolve().parent.parent / 'models'
_bundle = joblib.load(_MODELS / 'binary_pipeline.joblib')
_model, THRESHOLD = _bundle['model'], _bundle['threshold']
_model_mc = joblib.load(_MODELS / 'scamtype_pipeline.joblib')

LEVELS = ['Low', 'Medium', 'High', 'Very high']

def _level(p):
    if p >= 0.70: return 'Very high'
    if p >= 0.40: return 'High'
    if p >= 0.20: return 'Medium'
    return 'Low'

def analyze(message):
    message = str(message or '')
    text = decode_text(message)
    processed = preprocess_text(text)

    if len(processed.split()) < 2:
        return dict(score=None, level='Low', bumped_by_rules=False, types=[],
                    signals=[], advice=explain.GENERAL[:2],
                    note='This message is too short to assess.')

    row = pd.concat([pd.DataFrame({'processed_message': [processed]}),
                     features_df(pd.Series([text]))], axis=1)
    prob = float(_model.predict_proba(row)[0, 1])
    level = _level(prob)

    signals = explain.detect(text)
    keys = [s['key'] for s in signals]

    bumped = False
    if level == 'Low' and (set(keys) & {'credential', 'secrecy', 'upi_trick'} or len(keys) >= 3):
        level, bumped = 'Medium', True

    types = []
    if prob >= 0.20 or bumped:
        probs = _model_mc.predict_proba([processed])[0]
        order = np.argsort(probs)[::-1][:3]
        types = [(str(_model_mc.classes_[i]), float(probs[i])) for i in order]

    top_types = [t for t, p in types if p >= 0.20][:2]
    return dict(score=prob, level=level, bumped_by_rules=bumped, types=types,
                signals=signals, advice=explain.advice_for(top_types, keys), note='')
