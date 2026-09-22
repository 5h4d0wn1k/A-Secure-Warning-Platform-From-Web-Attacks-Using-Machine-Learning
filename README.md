> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# A Secure Warning Platform Against Web Attacks Using Machine Learning

A machine-learning educational research project that detects **phishing
URLs**, **Denial-of-Service (DoS) traffic**, and **cross-site scripting (XSS)
payloads** with scikit-learn classifiers, Jupyter notebooks, and Flask demo
apps.

[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/A-Secure-Warning-Platform-From-Web-Attacks-Using-Machine-Learning)](https://github.com/5h4d0wn1k/A-Secure-Warning-Platform-From-Web-Attacks-Using-Machine-Learning/stargazers)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/A-Secure-Warning-Platform-From-Web-Attacks-Using-Machine-Learning)](https://github.com/5h4d0wn1k/A-Secure-Warning-Platform-From-Web-Attacks-Using-Machine-Learning/commits)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/A-Secure-Warning-Platform-From-Web-Attacks-Using-Machine-Learning)](https://github.com/5h4d0wn1k/A-Secure-Warning-Platform-From-Web-Attacks-Using-Machine-Learning/issues)

Machine-learning based web-attack warning platform covering Phishing, DoS and
XSS detection with trained classifiers, feature engineering, and a front-end
demonstration.

## Why this project

Web attacks are increasingly automated, and ML offers a way to generalize
detection beyond fixed signatures. This repository is a learning-oriented
implementation of that idea: it applies classic and ensemble classifiers to
well-known datasets — a URL dataset for **phishing detection**, the **NSL-KDD**
dataset for intrusion/DoS detection, and an XSS payload corpus for script
detection — then wraps the trained models in simple Flask demos. Studying the
notebooks teaches feature extraction, model comparison, and accuracy
measurement on real security datasets. Everything here is for **educational
and authorized use** (e.g., your own lab web app, academic coursework).

## Features

- **Phishing URL detection** — `Phishing URL Detection` Flask app with
  gradient-boosting classifier and a 16-feature URL extractor
  (`feature.py`), trained on `urldata.csv`, served by `app.py`.
- **DoS / intrusion detection** — `DoS Attack (Intrusion Detection System)`
  Flask app using the `NSL KDD` dataset (feature engineering via dummies and
  outlier capping) and a persisted `model.pkl` to classify
  `NORMAL / DOS / PROBE / R2L / U2R`.
- **XSS detection** — `XSS` notebook and script (`XSS.PY`) comparing
  LogisticRegression, RandomForest, SVC, GaussianNB, and a Keras network over
  a `CountVectorizer` bag-of-words on `XSS_dataset.csv`.
- **Notebooks** — step-by-step Jupyter walkthroughs for every detector,
  including `pandas_profiling.html` for DoS data exploration.
- **Demo front-end** — `Front-End Code/index.html` landing page tying the
  project together.
- **Deployable Flask apps** — `Procfile` (Gunicorn) and a `Dockerfile` for the
  intrusion-detection app.

## Quickstart

Prerequisites: Python 3, scikit-learn, pandas, numpy, flask, jupyter.

```bash
# Explore the training and evaluation notebooks
jupyter notebook "Phishing Attack/Phishing-URL-Detection-master/Phishing-URL-Detection-master/Phishing URL Detection.ipynb"
jupyter notebook "DoS Attack (Intrusion Detection System)/Network Intrusion Detection System (DoS Attack)/Network Intrusion Detection System.ipynb"
jupyter notebook "XSS (Cross Site Scripting)/XSStrike-master/XSS_dataset.csv (1)/XSS.ipynb"

# Run the phishing detection web app (data + model artifacts are in the folder)
cd "Phishing Attack/Phishing-URL-Detection-master/Phishing-URL-Detection-master"
python app.py

# Run the DoS/intrusion detection web app (model.pkl is committed)
cd "../../../DoS Attack (Intrusion Detection System)/Network Intrusion Detection System (DoS Attack)"
python app.py
```

## Project structure

```
Phishing Attack/.../    phishing URL detector: feature.py, app.py, urldata.csv
DoS Attack (Intrusion Detection System)/...  NSL-KDD detector: app.py, model.pkl, notebooks
XSS (Cross Site Scripting)/...   XSS classifier: XSS.PY, XSS_dataset.csv, notebook
Front-End Code/         static landing page (index.html, style.css, images)
```

## Documentation

- [ETHICS.md](ETHICS.md) and [SCOPE.md](SCOPE.md) — authorized-use rules for
  this educational project.
- [SECURITY.md](SECURITY.md) — responsible disclosure.
- [CONTRIBUTING.md](CONTRIBUTING.md) / [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
  — community guidelines.

## Notes

The dataset paths inside the notebooks and `app.py` are machine-specific
(hardcoded Windows paths in places) — update them to your local checkout. The
intrusion-detection `Dockerfile` expects a `requirements.txt` at build time;
add one with Flask, scikit-learn, pandas, numpy, and joblib before building.

## License

[MIT](LICENSE). Educational deliverable — run it only against your own data,
your own lab, or data you are authorized to analyze.