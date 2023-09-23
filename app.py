from fastapi import FastAPI
from models import UrlInput

# Importing libraries
import pandas as pd
import re
import ipaddress
from urllib.parse import urlparse
import whois
import requests
from datetime import datetime
import pickle

app = FastAPI(
    title="Phishing Website Detection",
    description="Phishing Website Detection project's FastAPI Swagger documentation",
    openapi_tags=[
        {
            "name": "Health",
            "description": "Check Health status of Server",
        },
        {
            "name": "Phishing Detection",
            "description": "Powerful tool for scanning and investigating suspicious URLs.",
        },
    ]
)


@app.get("/", tags=["Health"])
def health_status():
    return {"Health": "OK"}


# Function to extract features from a URL
def extract_features_from_url(url):
    # Helper function to get the domain from a URL
    def get_domain(url):
        domain = urlparse(url).netloc
        if re.match(r"^www.", domain):
            domain = domain.replace("www.", "")
        return domain

    # Helper function to check for the presence of an IP address in the URL
    def having_ip(url):
        try:
            ipaddress.ip_address(url)
            ip = 1
        except:
            ip = 0
        return ip

    # Helper function to check for the presence of '@' symbol in the URL
    def have_at_sign(url):
        if "@" in url:
            at = 1
        else:
            at = 0
        return at

    # Helper function to compute the length of the URL
    def get_length(url):
        if len(url) < 54:
            length = 0
        else:
            length = 1
        return length

    # Helper function to compute the depth of the URL
    def get_depth(url):
        s = urlparse(url).path.split("/")
        depth = 0
        for j in range(len(s)):
            if len(s[j]) != 0:
                depth = depth + 1
        return depth

    # Helper function to check for the presence of "//" in the URL
    def redirection(url):
        pos = url.rfind("//")
        if pos > 6:
            if pos > 7:
                return 1
            else:
                return 0
        else:
            return 0

    # Helper function to check for the presence of "http/https" in the domain part of the URL
    def http_domain(url):
        domain = urlparse(url).netloc
        if "https" in domain:
            return 1
        else:
            return 0

    # Helper function to check for the use of URL shortening services
    def tiny_url(url):
        shortening_services = (
            r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
            r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
            r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
            r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|"
            r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|"
            r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|"
            r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"
            r"tr\.im|link\.zip\.net"
        )
        match = re.search(shortening_services, url)
        if match:
            return 1
        else:
            return 0

    # Helper function to check for the presence of '-' in the domain part of the URL
    def prefix_suffix(url):
        if "-" in urlparse(url).netloc:
            return 1  # phishing
        else:
            return 0  # legitimate

    # Helper function to check for the availability of DNS records for the hostname
    def dns_record(domain_name):
        try:
            domain_info = whois.whois(domain_name)
            return 0
        except:
            return 1

    # Helper function to check the web traffic of the URL
    def web_traffic(url):
        return 1  # Placeholder, you may implement the actual logic using web traffic data sources

    # Helper function to compute the age of the domain
    def domain_age(domain_name):
        try:
            domain_info = whois.whois(domain_name)
            creation_date = domain_info.creation_date
            expiration_date = domain_info.expiration_date
            if isinstance(creation_date, str) or isinstance(expiration_date, str):
                try:
                    creation_date = datetime.strptime(
                        str(creation_date), "%Y-%m-%d %H:%M:%S"
                    )
                    expiration_date = datetime.strptime(
                        str(expiration_date), "%Y-%m-%d %H:%M:%S"
                    )
                except:
                    return 1
            if (expiration_date is None) or (creation_date is None):
                return 1
            elif (type(expiration_date) is list) or (type(creation_date) is list):
                return 1
            else:
                age_of_domain = abs((expiration_date - creation_date).days)
                if (age_of_domain / 30) < 6:
                    age = 1
                else:
                    age = 0
            return age
        except:
            return 1

    # Helper function to compute the remaining domain time before expiration
    def domain_end(domain_name):
        try:
            domain_info = whois.whois(domain_name)
            expiration_date = domain_info.expiration_date
            if isinstance(expiration_date, str):
                try:
                    expiration_date = datetime.strptime(
                        str(expiration_date), "%Y-%m-%d %H:%M:%S"
                    )
                except:
                    return 1
            if expiration_date is None:
                return 1
            elif type(expiration_date) is list:
                return 1
            else:
                today = datetime.now()
                end = abs((expiration_date - today).days)
                if (end / 30) < 6:
                    end = 0
                else:
                    end = 1
            return end
        except:
            return 1

    # Helper function to check for the presence of "iframe" tags in the webpage source code
    def iframe(response):
        if not response:
            return 1
        else:
            if re.findall(r"[<iframe>|<frameBorder>]", response.text):
                return 0
            else:
                return 1

    # Helper function to check the effect of mouse over on the status bar
    def mouse_over(response):
        if not response:
            return 1
        else:
            if re.findall("<script>.+onmouseover.+</script>", response.text):
                return 1
            else:
                return 0

    # Helper function to check the status of the right-click attribute
    def right_click(response):
        if not response:
            return 1
        else:
            if re.findall(r"event.button ?== ?2", response.text):
                return 0
            else:
                return 1

    # Helper function to check the number of forwardings in the URL
    def web_forwards(url):
        try:
            response = requests.get(url)
            if response.status_code == 200:
                return 0
            else:
                return 1
        except:
            return 1

    # Extract features
    ip_present = having_ip(url)
    at_present = have_at_sign(url)
    url_len = get_length(url)
    url_depth = get_depth(url)
    redirection_present = redirection(url)
    https_in_domain = http_domain(url)
    tinyurl_present = tiny_url(url)
    prefix_suffix_present = prefix_suffix(url)
    dns_rec = dns_record(get_domain(url))
    web_traffic_status = web_traffic(url)
    domain_age_status = domain_age(get_domain(url))
    domain_end_status = domain_end(get_domain(url))

    # As web_forwards function requires an actual request to the URL, we'll handle it separately
    try:
        response = requests.get(url)
        web_forwards_status = web_forwards(url)
    except:
        response = None
        web_forwards_status = 1

    # Create an array of the extracted features
    features_array = [
        ip_present,
        at_present,
        url_len,
        url_depth,
        redirection_present,
        https_in_domain,
        tinyurl_present,
        prefix_suffix_present,
        dns_rec,
        web_traffic_status,
        domain_age_status,
        domain_end_status,
        iframe(response),
        mouse_over(response),
        right_click(response),
        web_forwards_status,
    ]

    return features_array


@app.post("/Analyzer_URL/", tags=["Phishing Detection"])
def Analyzer_URL(urldata: UrlInput):
    try:
        # Fetching the feature set for input URL
        features = extract_features_from_url(urldata.url)

        # Load the XGBoost model
        loaded_model = pickle.load(open("XGBoostClassifier.pickle.dat", "rb"))

        # Convert the preprocessed URL data to a DataFrame (assuming it's in the same format as the training data)
        feature_names = [
            "Have_IP",
            "Have_At",
            "URL_Length",
            "URL_Depth",
            "Redirection",
            "https_Domain",
            "TinyURL",
            "Prefix/Suffix",
            "DNS_Record",
            "Web_Traffic",
            "Domain_Age",
            "Domain_End",
            "iFrame",
            "Mouse_Over",
            "Right_Click",
            "Web_Forwards",
        ]
        url_df = pd.DataFrame([features], columns=feature_names)

        # Predict the label using the loaded XGBoost model
        prediction = loaded_model.predict(url_df)

        # Print the prediction (1 for phishing, 0 for legitimate)
        result = "Phishing URL" if prediction[0] == 1 else "Legitimate URL"
        return {"url": result}

    except Exception as e:
        return {"error": str(e)}
