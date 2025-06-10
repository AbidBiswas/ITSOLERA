import requests

def domain_report(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})

        return {
            "categories": attributes.get("categories", {}),
            "reputation": attributes.get("reputation", "N/A"),
            "last_analysis": attributes.get("last_analysis_stats", {})
        }
    else:
        return {"error": f"Failed to retrieve data: {response.status_code} - {response.text}"}
