import json
import uuid
from datetime import datetime
from stix2 import Indicator, Bundle, ObservedData, File, Identity, ExternalReference
from taxii2client.v21 import Server, Collection
import argparse
import os

MATCH_FILE = "results/yara_matches.json"
STIX_BUNDLE_OUT = "results/stix_yara_bundle.json"

def generate_stix_bundle(yara_matches, firmware_path):
    indicators = []
    observed = []
    ts = datetime.utcnow().isoformat()

    src_identity = Identity(
        id="identity--" + str(uuid.uuid4()),
        name="Satellite Defense Toolkit",
        identity_class="tool"
    )

    for match in yara_matches:
        rule_name = match.get("rule", "unknown")
        rule_id = "indicator--" + str(uuid.uuid4())
        pattern = f"[file:content_ref MATCHES '{rule_name}']"

        indicators.append(Indicator(
            id=rule_id,
            name=rule_name,
            description="Auto-exported YARA rule match",
            pattern=pattern,
            pattern_type="stix",
            valid_from=ts,
            created_by_ref=src_identity.id,
            external_references=[
                ExternalReference(source_name="yara_rule", description=str(match))
            ]
        ))

        observed.append(ObservedData(
            id="observed-data--" + str(uuid.uuid4()),
            first_observed=ts,
            last_observed=ts,
            number_observed=1,
            created_by_ref=src_identity.id,
            objects={
                "0": File(name=os.path.basename(firmware_path))
            }
        ))

    bundle = Bundle(objects=[src_identity] + indicators + observed)
    return bundle

def export_to_taxii(bundle, taxii_url, collection_name, username=None, password=None):
    server = Server(taxii_url, user=username, password=password)
    api_root = server.api_roots[0]
    collection = None
    for c in api_root.collections:
        if c.title == collection_name:
            collection = c
            break
    if not collection:
        raise Exception("Collection not found")

    collection.add_objects(bundle)

def main():
    parser = argparse.ArgumentParser(description="Export YARA match results to STIX format")
    parser.add_argument("--firmware", required=True, help="Firmware path for reference")
    parser.add_argument("--taxii-url", help="Optional TAXII server URL")
    parser.add_argument("--taxii-collection", help="TAXII collection to publish to")
    parser.add_argument("--user", help="TAXII username")
    parser.add_argument("--password", help="TAXII password")

    args = parser.parse_args()

    if not os.path.exists(MATCH_FILE):
        print(f"[!] Match file not found: {MATCH_FILE}")
        return

    with open(MATCH_FILE, "r") as f:
        matches = json.load(f)

    bundle = generate_stix_bundle(matches, args.firmware)

    with open(STIX_BUNDLE_OUT, "w") as f:
        f.write(str(bundle))

    print(f"[✓] STIX bundle written to: {STIX_BUNDLE_OUT}")

    if args.taxii_url and args.taxii_collection:
        export_to_taxii(bundle, args.taxii_url, args.taxii_collection, args.user, args.password)
        print(f"[✓] STIX bundle sent to TAXII collection: {args.taxii_collection}")

if __name__ == "__main__":
    main()
