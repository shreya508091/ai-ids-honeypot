\# Hybrid AI-Based Intrusion Detection and Deception Platform



CMR College of Engineering \& Technology, Dept. of CSE (Cybersecurity), Major Project Phase-I, Batch B15.

Guide: Mrs. K. Sujitha.



\## Overview

A security prototype that combines machine-learning intrusion detection (Random Forest, SVM),

a honeypot (fake SSH and HTTP admin login), explainable AI (SHAP), a live dashboard,

and automated response (IP blocklist and administrator notifications).



\## Architecture

```mermaid

flowchart LR

&#x20;   A\[NSL-KDD traffic features] --> B\[Preprocessing]

&#x20;   B --> C\[Random Forest / SVM]

&#x20;   C --> D\[SHAP explanations]

&#x20;   C --> E\[Dashboard]

&#x20;   D --> E

&#x20;   F\[Honeypot: SSH + HTTP] --> G\[honeypot.jsonl]

&#x20;   G --> E

&#x20;   E --> H\[IP blocklist]

&#x20;   E --> I\[notifications.log]

```



\## Results (NSL-KDD, KDDTest+)

| Model | Accuracy | Attack precision | Attack recall |

|---|---|---|---|

| Random Forest | 0.773 | 0.966 | 0.623 |

| SVM | 0.782 | 0.976 | 0.633 |



Lowering the Random Forest decision threshold trades false alarms for more detected attacks:



| Threshold | Precision | Recall | F1 |

|---|---|---|---|

| 0.5 | 0.966 | 0.623 | 0.758 |

| 0.4 | 0.967 | 0.682 | 0.800 |

| 0.3 | 0.966 | 0.718 | 0.824 |

| 0.2 | 0.964 | 0.776 | 0.860 |

| 0.1 | 0.927 | 0.864 | 0.895 |



The dashboard uses a threshold of 0.2. KDDTest+ contains attack types absent from training,

which limits recall.



\## Setup (Windows)

&#x20;   python -m venv venv

&#x20;   venv\\Scripts\\Activate.ps1

&#x20;   python -m pip install -r requirements.txt



Download the dataset into `data/` (KDDTrain.txt, KDDTest.txt), then run notebooks 01 to 04 in `notebooks/`.



\## Run

&#x20;   python honeypot\\honeypot.py      (window 1)

&#x20;   python dashboard\\app.py          (window 2, open http://127.0.0.1:5000)



\## Project structure

\- `notebooks/` data exploration, preprocessing, model training, explainability

\- `honeypot/` SSH and HTTP honeypot

\- `dashboard/` Flask dashboard, severity, SHAP reasons, auto-block, notifications

\- `logs/` honeypot and notification logs (not committed)



\## Notes

Alerts in the dashboard replay NSL-KDD samples. Converting live traffic to the 41 NSL-KDD

features is future work. Run the honeypot only on a local or lab network.

