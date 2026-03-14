from flask import Flask, request, jsonify
import boto3
import json
import re
import requests
import time

app = Flask(__name__)

# AWS Bedrock client
bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')

CVE_ID_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

def fetch_cve_nist(cve_id):
    """Fetch CVE data from NIST NVD API 2.0"""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {'cveId': cve_id}

    time.sleep(0.6)  # ~1.6 requests per second to stay under rate limit

    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get('totalResults', 0) > 0:
            return data['vulnerabilities'][0]['cve']
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVE {cve_id}: {e}")
        return None

def extract_cve_info(cve_data):
    """Extract relevant information from NIST CVE data"""
    cve_info = {
        'id': cve_data.get('id', 'Unknown'),
        'description': '',
        'cvss_v3': None,
        'cvss_v2': None,
        'cvss_v4': None,
        'cwe': [],
        'references': [],
        'cpe_configurations': [],
        'published': cve_data.get('published', ''),
        'modified': cve_data.get('lastModified', '')
    }

    # Extract English description
    for desc in cve_data.get('descriptions', []):
        if desc.get('lang') == 'en':
            cve_info['description'] = desc.get('value', 'No description available')
            break

    metrics = cve_data.get('metrics', {})

    # CVSS v4
    cvss_v4 = metrics.get('cvssMetricV40')
    if cvss_v4:
        cvss_data = cvss_v4[0].get('cvssData', {})
        cve_info['cvss_v4'] = {
            'score': cvss_data.get('baseScore'),
            'severity': cvss_data.get('baseSeverity'),
            'vector': cvss_data.get('vectorString')
        }

    # CVSS v3.x
    cvss_v3 = metrics.get('cvssMetricV31') or metrics.get('cvssMetricV30')
    if cvss_v3:
        cvss_data = cvss_v3[0].get('cvssData', {})
        cve_info['cvss_v3'] = {
            'score': cvss_data.get('baseScore'),
            'severity': cvss_data.get('baseSeverity'),
            'vector': cvss_data.get('vectorString')
        }

    # CVSS v2
    cvss_v2 = metrics.get('cvssMetricV2')
    if cvss_v2:
        cvss_data = cvss_v2[0].get('cvssData', {})
        cve_info['cvss_v2'] = {
            'score': cvss_data.get('baseScore'),
            'severity': cvss_data.get('baseSeverity'),
            'vector': cvss_data.get('vectorString')
        }

    # CWE
    for weakness in cve_data.get('weaknesses', []):
        for desc in weakness.get('description', []):
            if desc.get('lang') == 'en':
                cve_info['cwe'].append(desc.get('value'))

    # References (limit to 5)
    for ref in cve_data.get('references', [])[:5]:
        cve_info['references'].append({
            'url': ref.get('url'),
            'source': ref.get('source'),
            'tags': ref.get('tags', [])
        })

    # Affected products from CPE configurations (limit to 10)
    for config in cve_data.get('configurations', []):
        for node in config.get('nodes', []):
            for cpe_match in node.get('cpeMatch', []):
                if cpe_match.get('vulnerable', False):
                    cpe_uri = cpe_match.get('criteria', '')
                    if cpe_uri and len(cve_info['cpe_configurations']) < 10:
                        cve_info['cpe_configurations'].append(cpe_uri)

    return cve_info

def generate_enhanced_prompt(cve_info):
    """Generate enhanced prompt with structured CVE data"""

    # Best available CVSS score
    if cve_info['cvss_v4']:
        cvss_info = f"CVSS v4: {cve_info['cvss_v4']['score']} ({cve_info['cvss_v4']['severity']}) - {cve_info['cvss_v4']['vector']}"
    elif cve_info['cvss_v3']:
        cvss_info = f"CVSS v3: {cve_info['cvss_v3']['score']} ({cve_info['cvss_v3']['severity']}) - {cve_info['cvss_v3']['vector']}"
    elif cve_info['cvss_v2']:
        cvss_info = f"CVSS v2: {cve_info['cvss_v2']['score']} ({cve_info['cvss_v2']['severity']}) - {cve_info['cvss_v2']['vector']}"
    else:
        cvss_info = "Not available"

    cwe_info = ', '.join(cve_info['cwe']) if cve_info['cwe'] else 'Not specified'

    products = []
    for cpe in cve_info['cpe_configurations'][:3]:
        parts = cpe.split(':')
        if len(parts) >= 5:
            products.append(f"{parts[3]} {parts[4]}")
    products_info = ', '.join(products) if products else 'Not specified'

    ref_urls = [ref['url'] for ref in cve_info['references'][:3]]
    references_info = '\n'.join(f"  - {url}" for url in ref_urls) if ref_urls else '  - Not available'

    severity = 'unknown'
    if cve_info['cvss_v4']:
        severity = cve_info['cvss_v4']['severity'].lower()
    elif cve_info['cvss_v3']:
        severity = cve_info['cvss_v3']['severity'].lower()
    elif cve_info['cvss_v2']:
        severity = cve_info['cvss_v2']['severity'].lower()

    return f"""You are a cybersecurity expert specializing in creating Nuclei templates. Create a comprehensive Nuclei template for the following CVE.

CVE ID: {cve_info['id']}
Description: {cve_info['description']}
Severity: {cvss_info}
Nuclei severity field value: {severity}
Weakness Type (CWE): {cwe_info}
Affected Products: {products_info}
References:
{references_info}
Published: {cve_info['published']}

Requirements:
1. Create a valid Nuclei YAML template following the latest Nuclei template format
2. Include appropriate HTTP requests for detection
3. Add relevant matchers based on the vulnerability type (status codes, response body, headers)
4. Include proper metadata: id, name, author, severity, description, reference, tags, cvss-metrics, cvss-score, cve-id, cwe-id
5. Use the exact severity value provided above in the info block
6. Add meaningful description and all references listed above
7. Consider the specific products/technologies affected when crafting requests and matchers
8. For the tags field include: cve, {cve_info['id'].lower()}, and any relevant technology tags

Return ONLY the YAML template without any additional text, markdown code fences, or explanations.
"""

def call_bedrock(prompt):
    response = bedrock.invoke_model(
        modelId="anthropic.claude-3-5-haiku-20241022-v1:0",
        contentType="application/json",
        accept="application/json",
        body=json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 4096,
            "temperature": 0.2
        })
    )
    result = json.loads(response['body'].read())
    return result['content'][0]['text']

@app.route('/generate', methods=['POST'])
def generate():
    data = request.json
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    cve_id = (data.get('cve_id') or data.get('id') or '').strip().upper()

    if not cve_id:
        return jsonify({"error": "Missing CVE ID"}), 400

    if not CVE_ID_PATTERN.match(cve_id):
        return jsonify({"error": "Invalid CVE ID format. Expected format: CVE-YYYY-NNNNN"}), 400

    cve_data = fetch_cve_nist(cve_id)
    if not cve_data:
        return jsonify({"error": f"CVE {cve_id} not found in NVD or API error"}), 404

    try:
        cve_info = extract_cve_info(cve_data)
        prompt = generate_enhanced_prompt(cve_info)
        template = call_bedrock(prompt)

        return jsonify({
            "template": template,
            "cve_info": cve_info
        })
    except Exception as e:
        print(f"Error generating template for {cve_id}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"})

if __name__ == '__main__':
    app.run(port=5000, debug=True)
