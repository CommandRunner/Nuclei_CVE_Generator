```
from flask import Flask, request, jsonify
import boto3
import json
import requests
import time

app = Flask(__name__)

# AWS Bedrock client
bedrock = boto3.client('bedrock-runtime', region_name='us-east-1')

def fetch_cve_nist(cve_id):
    """Fetch CVE data from NIST NVD API 2.0"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'cveId': cve_id
    }

    # Add delay to respect rate limits
    time.sleep(0.6)  # ~1.6 requests per second to stay under limit

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
        'cwe': [],
        'references': [],
        'cpe_configurations': [],
        'published': cve_data.get('published', ''),
        'modified': cve_data.get('lastModified', '')
    }

    # Extract description
    descriptions = cve_data.get('descriptions', [])
    for desc in descriptions:
        if desc.get('lang') == 'en':
            cve_info['description'] = desc.get('value', 'No description available')
            break

    # Extract CVSS scores
    metrics = cve_data.get('metrics', {})

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

    # Extract CWE
    weaknesses = cve_data.get('weaknesses', [])
    for weakness in weaknesses:
        for desc in weakness.get('description', []):
            if desc.get('lang') == 'en':
                cve_info['cwe'].append(desc.get('value'))

    # Extract references
    references = cve_data.get('references', [])
    for ref in references[:5]:  # Limit to 5 references
        cve_info['references'].append({
            'url': ref.get('url'),
            'source': ref.get('source'),
            'tags': ref.get('tags', [])
        })

    # Extract CPE configurations (affected products)
    configurations = cve_data.get('configurations', [])
    for config in configurations:
        for node in config.get('nodes', []):
            for cpe_match in node.get('cpeMatch', []):
                if cpe_match.get('vulnerable', False):
                    cpe_uri = cpe_match.get('criteria', '')
                    if cpe_uri:
                        cve_info['cpe_configurations'].append(cpe_uri)

    return cve_info

def generate_enhanced_prompt(cve_info):
    """Generate enhanced prompt with structured CVE data"""

    # Format CVSS information
    cvss_info = "Not available"
    if cve_info['cvss_v3']:
        cvss_info = f"CVSS v3: {cve_info['cvss_v3']['score']} ({cve_info['cvss_v3']['severity']})"
    elif cve_info['cvss_v2']:
        cvss_info = f"CVSS v2: {cve_info['cvss_v2']['score']} ({cve_info['cvss_v2']['severity']})"

    # Format CWE information
    cwe_info = ', '.join(cve_info['cwe']) if cve_info['cwe'] else 'Not specified'

    # Format affected products (simplified CPE)
    products = []
    for cpe in cve_info['cpe_configurations'][:3]:  # Limit to 3
        # Simplify CPE format for readability
        parts = cpe.split(':')
        if len(parts) >= 5:
            vendor = parts[3]
            product = parts[4]
            products.append(f"{vendor} {product}")

    products_info = ', '.join(products) if products else 'Not specified'

    # Format references
    ref_urls = [ref['url'] for ref in cve_info['references'][:3]]
    references_info = ', '.join(ref_urls) if ref_urls else 'Not available'

    return f"""
You are a cybersecurity expert specializing in creating Nuclei templates. Create a comprehensive Nuclei template for this CVE:

CVE ID: {cve_info['id']}
Description: {cve_info['description']}
Severity: {cvss_info}
Weakness Type (CWE): {cwe_info}
Affected Products: {products_info}
References: {references_info}
Published: {cve_info['published']}

Requirements:
1. Create a valid Nuclei YAML template
2. Include appropriate HTTP requests for detection
3. Add relevant matchers based on the vulnerability type
4. Include proper metadata (author, severity, tags)
5. Add meaningful description and references
6. Consider the specific products/technologies affected

Return ONLY the YAML template without any additional text or explanations.
"""

def call_bedrock(prompt):
    response = bedrock.invoke_model(
        modelId="anthropic.claude-3-haiku-20240307-v1:0",
        contentType="application/json",
        accept="application/json",
        body=json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 2048,  # Increased for more detailed templates
            "temperature": 0.2   # Lower temperature for more consistent output
        })
    )
    result = json.loads(response['body'].read())
    return result['content'][0]['text']

@app.route('/generate', methods=['POST'])
def generate():
    data = request.json
    cve_id = data.get('cve_id') or data.get('id')

    if not cve_id:
        return jsonify({"error": "Missing CVE ID"}), 400

    # Validate CVE ID format
    if not cve_id.startswith('CVE-'):
        return jsonify({"error": "Invalid CVE ID format. Must start with 'CVE-'"}), 400

    cve_data = fetch_cve_nist(cve_id)
    if not cve_data:
        return jsonify({"error": "CVE not found or API error"}), 404

    try:
        cve_info = extract_cve_info(cve_data)
        prompt = generate_enhanced_prompt(cve_info)
        template = call_bedrock(prompt)

        return jsonify({
            "template": template,
            "cve_info": cve_info  # Optional: return structured data too
        })
    except Exception as e:
        print(f"Error generating template for {cve_id}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy"})

if __name__ == '__main__':
    app.run(port=5000, debug=True)
```
