## modules/ai/threat_classifier.py
import torch, torch.nn as nn
from transformers import BertTokenizer, BertModel
import argparse

MITRE_CLASSES = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
                 "Credential Access", "Discovery", "Lateral Movement", "Collection", "Exfiltration", "Command and Control"]

class ThreatClassifier(nn.Module):
    def __init__(self):
        super().__init__()
        self.bert = BertModel.from_pretrained("bert-base-uncased")
        self.fc = nn.Linear(768, len(MITRE_CLASSES))
    def forward(self, input_ids, attention_mask):
        _, pooled = self.bert(input_ids=input_ids, attention_mask=attention_mask, return_dict=False)
        return self.fc(pooled)

def classify(text, model, tokenizer):
    tokens = tokenizer(text, return_tensors="pt", truncation=True, padding=True)
    with torch.no_grad(): logits = model(**tokens)
    return MITRE_CLASSES[torch.argmax(logits).item()]

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    args = parser.parse_args()

    model = ThreatClassifier(); model.eval()
    tokenizer = BertTokenizer.from_pretrained("bert-base-uncased")

    with open(args.log) as f:
        for line in f:
            if line.strip(): print(f"[{classify(line.strip(), model, tokenizer)}] {line.strip()}")
