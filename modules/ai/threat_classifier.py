# modules/ai/threat_classifier.py

import torch
import torch.nn as nn
from transformers import BertTokenizer, BertModel
import argparse
import os
import json
from datetime import datetime

MITRE_CLASSES = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "Command and Control"
]

class ThreatClassifier(nn.Module):
    def __init__(self):
        super().__init__()
        self.bert = BertModel.from_pretrained("bert-base-uncased")
        self.classifier = nn.Linear(768, len(MITRE_CLASSES))

    def forward(self, input_ids, attention_mask):
        _, pooled = self.bert(input_ids=input_ids, attention_mask=attention_mask, return_dict=False)
        return self.classifier(pooled)

def classify(text, model, tokenizer):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True)
    with torch.no_grad():
        logits = model(**inputs)
        probs = torch.softmax(logits, dim=1).squeeze()
    pred_idx = torch.argmax(probs).item()
    return MITRE_CLASSES[pred_idx], probs.tolist()

def save_result(entry, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "a") as f:
        f.write(json.dumps(entry) + "\n")

def main(args):
    print("[+] Loading model and tokenizer...")
    model = ThreatClassifier()
    model.eval()
    tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")

    output_path = "results/threat_classification.jsonl"

    print(f"[+] Classifying lines from: {args.log}")
    with open(args.log, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            label, confidences = classify(line, model, tokenizer)
            result = {
                "timestamp": datetime.utcnow().isoformat(),
                "text": line,
                "predicted_class": label,
                "confidences": dict(zip(MITRE_CLASSES, [round(c, 4) for c in confidences]))
            }
            print(f"[{label}] {line}")
            save_result(result, output_path)

    print(f"[✓] Classification results saved to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MITRE TTP Text Classifier")
    parser.add_argument("--log", required=True, help="Log file or raw text lines")
    args = parser.parse_args()
    main(args)
