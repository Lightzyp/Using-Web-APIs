# Using-Web-APIs


Daniel Macharia
March 3, 2026

The API I used is https://www.virustotal.com/api/v3 The purpose of this API is to Analyze suspicious files, domains, IPs, and URLs to detect malware and other breaches, automatically share them with the user that is running threatcheck.py

Endpoint Documentation

GET Scan IP Address

 URL Path: GET https://www.virustotal.com/api/v3/ip_addresses/{ip
Replace {ip} with the target IPv4 or IPv6 address, e.g.:

GET https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8

JSON Sent to API
No request body is sent. Authentication is provided via the request header only:

Headers: x-apikey: 6a0fa6fd91bc11fc5204bc147a83acc41ea86c9616c4162ec40d8bf43f72db6e


 JSON Response from API
{
"data": {
  "id": "8.8.8.8"
  "type": "ip_address"
"attributes": {
  "country": "US",
 "reputation": 0
 "last_analysis_stats": 
 "harmless": 72
  "malicious": 1,
 "suspicious": 0,
  "undetected": 1     
 }
  }
 }
}

Description
This endpoint retrieves threat intelligence for a given IP address. The tool extracts the country, reputation score, and last_analysis_stats — a summary of how many antivirus/security engines flagged the IP as harmless, malicious, suspicious, or undetected.

GET Scan Domain

 URL Path
GET https://www.virustotal.com/api/v3/domains/{domain}
Replace {domain} with the target domain name, e.g.:
GET https://www.virustotal.com/api/v3/domains/example.com

 JSON Sent to API
No request body is sent. Authentication is provided via the request header:
Headers: x-apikey: 6a0fa6fd91bc11fc5204bc147a83acc41ea86c9616c4162ec40d8bf43f72db6e


JSON Response from API

{
  "data": {
"id": "example.com",
"type": "domain"
"attributes": {
"creation_date": 82045
 "reputation"
"last_analysis_stat
  "harmless
  "malicious": 
 "suspicious": 0,
"undetected": 2
   }
 }

Description:
This endpoint returns threat intelligence for a domain name. ThreatCheck passes the creation_date (a UNIX timestamp, converted to human-readable format via format_timestamp()) and the last_analysis_stats to show how security engines have assessed the domain.

POST Scan URL (Submit)
URL Path: POST https://www.virustotal.com/api/v3/urls
JSON Sent to API:
A POST request with a JSON body containing the target URL is submitted:
Headers: 
x-apikey: 6a0fa6fd91bc11fc5204bc147a83acc41ea86c9616c4162ec40d8bf43f72db6e
 Content-Type: application/json
 Body:
{
    "url": "https://suspicious-site.example.com"
}
JSON Response from API (Submit)
{
    "data": {
        "type": "analysis",
        "id": "u-3a9f2c7e1b4d6f8a0c2e5b7d9f1a3c5e7b9d1f3a5c7e9b-1709500000"
    }
}
 Description
The URL scan workflow involves two API calls. First, the URL is submitted via POST to /urls. VirusTotal queues it for analysis and returns an analysis ID. ThreatCheck then immediately uses that ID to retrieve the analysis result (see Endpoint 3b below). This two-step approach is required because URL analysis is asynchronous on VirusTotal's backend.

GET Scan URL  (Fetch Result)
URL Path:GET https://www.virustotal.com/api/v3/analyses/{analysis_id}
The {analysis_id} value is taken from the response of the POST /urls call above
GET https://www.virustotal.com/api/v3/analyses/u-3a9f2c7e1b4d6f8a0c2e5b7d9f1a3c5e7b9d1f3a5c7e9b-1709500000
JSON Sent to API
No request body is sent. Only the auth header is required:
Headers: x-apikey: 6a0fa6fd91bc11fc5204bc147a83acc41ea86c9616c4162ec40d8bf43f72db6eJSON Response from API
{
    "data": {
        "type": "analysis",
        "id": "u-3a9f2c7e1b4d6f8a0c2e5b7d9f1a3c5e7b9d1f3a5c7e9b-1709500000",
        "attributes": {
            "status": "completed",
  "stats”:
   "harmless": 65,
   "malicious": 3,
   "suspicious": 1,
    "undetected": 20
            }
        }
    }
}
Description
After retrieving the analysis ID from Step 3, ThreatCheck fetches the analysis result using GET /analyses/{id}. The stats field (note: not last_analysis_stats, but stats for analysis objects) is extracted and displayed. The two-call pattern mirrors how VirusTotal's asynchronous scanning pipeline works.

GET Scan File Hash
URL Path: GET https://www.virustotal.com/api/v3/files/{hash}
Accepts MD5, SHA-1, or SHA-256 hash values, e.g.:
GET https://www.virustotal.com/api/v3/files/0aef6fecd4d1f98e0912156abc64dedc
JSON Sent to API
No request is sent. Authentication is provided via the request header:
Headers: x-apikey: 6a0fa6fd91bc11fc5204bc147a83acc41ea86c9616c4162ec40d8bf43f72db6e
JSON Response from API
{
    "data": {
        "id": "0aef6fecd4d1f98e0912156abc64dedc",
        "type": "file",
        "attributes": {
            "meaningful_name": "malware_sample.exe",
            "type_description": "Win32 EXE",
            "size": 204800,
            "last_analysis_stats": {
                "harmless": 5,
                "malicious": 58,
                "suspicious": 3,
                "undetected": 8
            }
        }
    }
}
 Description
This endpoint queries VirusTotal's file database using a known hash (MD5, SHA-1, or SHA-256). ThreatCheck uses this for hash-based IOC (Indicator of Compromise) lookups — a common step in malware analysis and incident response. The last_analysis_stats reveal how many of VirusTotal's ~70+ AV engines flagged the file. This endpoint does not upload any file; it only looks up previously submitted hashes.
