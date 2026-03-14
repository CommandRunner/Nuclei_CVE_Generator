# Nuclei CVE Generator

A Flask API that automatically generates [Nuclei](https://github.com/projectdiscovery/nuclei) templates for CVEs using AWS Bedrock (Claude) and data from the NIST NVD API.

---

## How It Works

1. You send a CVE ID to the `/generate` endpoint
2. It fetches the CVE details from the [NIST NVD API](https://nvd.nist.gov/developers/vulnerabilities)
3. It builds a structured prompt with the CVE metadata (CVSS score, CWE, affected products, references)
4. It sends the prompt to Claude via AWS Bedrock
5. Returns a ready-to-use Nuclei YAML template

---

## Requirements

- Python 3.9+
- AWS account with Bedrock access (Claude model enabled in `us-east-1`)
- AWS credentials configured (`~/.aws/credentials` or environment variables)

---

## Installation

```bash
git clone https://github.com/CommandRunner/Nuclei_CVE_Generator
cd Nuclei_CVE_Generator
pip install -r requirements.txt
```

---

## Usage

**Start the server:**
```bash
python main.py
```

**Generate a template:**
```bash
curl -X POST http://localhost:5000/generate \
  -H "Content-Type: application/json" \
  -d '{"cve_id": "CVE-2021-44228"}'
```

**Response:**
```json
{
  "template": "id: CVE-2021-44228\ninfo:\n  name: ...",
  "cve_info": {
    "id": "CVE-2021-44228",
    "description": "...",
    "cvss_v3": { "score": 10.0, "severity": "CRITICAL", "vector": "..." },
    ...
  }
}
```

**Health check:**
```bash
curl http://localhost:5000/health
```

---

## AWS Setup

Make sure you have AWS credentials configured and that the Claude model is enabled in Bedrock:

```bash
aws configure
```

The model used is `anthropic.claude-3-5-haiku-20241022-v1:0` in `us-east-1`. You can enable models in the [AWS Bedrock console](https://console.aws.amazon.com/bedrock/home#/modelaccess).

---

## Security Notice

- Use only on authorized targets.
- Generated templates are AI-produced — always review before running against production systems.
