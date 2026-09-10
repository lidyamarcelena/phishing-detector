# library
import re
import os
import math
import socket
import ipaddress
from collections import Counter
import Levenshtein
from urllib.parse import urlparse
import pandas as pd
import tldextract
import requests
from bs4 import BeautifulSoup


# hints phish word
HINTS = [
    'wp', 'login', 'admin', 'content', 'images', 'js', 'css', 'myaccount', 'dropbox', 
    'themes', 'plugins', 'signin', 'view', 'click', 'mailbox', 'link', 'verify', 
    'customer', 'access', 'dear', 'log', 'paypal', 'secure', 
    'service', 'protect', 'mail', 'clicking' # https://www.mdpi.com/1099-4300/23/2/182
]

# brand list - done
def txt_to_list(txt_object):
    lst = []
    for line in txt_object:
        lst.append(line.strip())
    txt_object.close()
    return lst

allbrand = txt_to_list(open(r"D:\skripsi\dataset\allbrands.txt", "r")) #brandspurng & kaspersky

# url parser - done
def parse_url(url):
    parsed = urlparse(url)

    scheme = parsed.scheme
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    full_url = url
    base_url = scheme + "://" + hostname + path

    words_raw = re.split(r'\W+', full_url)
    words_host = re.split(r'\W+', hostname)
    words_path = re.split(r'\W+', path)

    return scheme, full_url, base_url, hostname, path, query, words_raw, words_host, words_path

# URL-BASED FEATURES (1–55) 

# 1. url_length - done
def url_length(full_url):
    return len(full_url)

# 2. hostname_length - done
def hostname_length(hostname):
    return len(hostname)

# 3. has_ip - done
def having_ip_address(full_url):
    parsed = urlparse(full_url)
    host = parsed.hostname or ""
    path = parsed.path or ""

    # IP sebagai HOST 
    try:
        ipaddress.ip_address(host)
        return 1
    except:
        pass

    # IPv4 hex sebagai HOST
    if re.fullmatch(r"(0x[0-9a-fA-F]{1,2}\.){3}0x[0-9a-fA-F]{1,2}", host):
        return 1

    # IP di PATH 
    if re.search(r"\b(\d{1,3}\.){3}\d{1,3}\b", path):
        return 1
    return 0

# 4. count_dot - done
def count_dot(hostname):
    return hostname.count('.')

# 5. count_hyphen - done
def count_hyphen(base_url):
    return base_url.count('-')

# 6. count_at - done
def count_at(base_url):
    return base_url.count('@')

# 7. count_question - done
def count_question(full_url):
    return full_url.count('?')

# 8. count_ampersand - done
def count_ampersand(full_url):
    return full_url.count('&')

# 9. count_pipe - done
def count_pipe(full_url):
    return full_url.count('|') + full_url.count('%7C')

# 10. count_equal - done
def count_equal(full_url):
    return full_url.count('=')

# 11. count_underscore - done
def count_underscore(base_url):
    return base_url.count('_')

# 12. count_tilde - done
def count_tilde(full_url):
    return 1 if '~' in full_url else 0

# 13. count_percent - done
def count_percent(full_url):
    return full_url.count('%')

# 14. count_slash - done
def count_slash(full_url):
    return full_url.count('/')

# 15. count_asterisk - done
def count_asterisk(full_url):
    return full_url.count('*')

# 16. count_colon - done
def count_colon(full_url):
    return full_url.count(':')

# 17. count_comma - done
def count_comma(base_url):
    return base_url.count(',')

# 18. count_semicolon - done
def count_semicolon(full_url):
    return full_url.count(';')

# 19. count_dollar - done
def count_dollar(base_url):
    return base_url.count('$')

# 20. count_space - done
def count_space(full_url):
    return full_url.count(' ') + full_url.count('%20')

# 21. count_www - done
def count_www(words_raw):
    return sum(1 for w in words_raw if 'www' in w)

# 22. count_com - done
def count_com(words_raw):
    return sum(1 for w in words_raw if 'com' in w)

# 23. count_http - done
def count_http_token(path):
    return path.count('http')

# 24. count_double_slash - done
def count_double_slash(full_url):
    positions = [m.start() for m in re.finditer('//', full_url)]
    return 1 if positions and positions[-1] > 6 else 0

# 25. has_https - done
def https_token(scheme):
    return 0 if scheme == 'https' else 1

# 26. digit_ratio_url - done
def digit_ratio_url(full_url):
    return len(re.sub(r'\D', '', full_url)) / len(full_url)

# 27. digit_ratio_host - done
def ratio_digits(hostname):
    return len(re.sub(r'\D', '', hostname)) / len(hostname) if len(hostname) > 0 else 0

# 28. has_punycode - done
def punycode(full_url):
    return 1 if 'xn--' in full_url else 0

# 29. has_port - done
def port(full_url):
    parsed = urlparse(full_url)
    return 1 if parsed.port else 0

# 30. tld_in_path - done
def tld_in_path(tld, path):
    return 1 if tld in path.lower() else 0

# 31. tld_in_subdomain - done
def tld_in_subdomain(tld, subdomain):
    return 1 if tld in subdomain.lower() else 0

# 32. abnormal_subdomain - done
def abnormal_subdomain(full_url):
    return 1 if re.search(r'(http[s]?://(w[w]?|\d))', full_url) else 0

# 33. subdomain_count - done
def count_subdomain(hostname):
    return hostname.count('.') if hostname else 0

# 34. prefix_suffix - done
def prefix_suffix(full_url):
    return 1 if re.findall(r"https?://[^\-]+-[^\-]+/", full_url) else 0

# 35. random_domain - done
def random_domain(domain, threshold=3.5):
    domain = domain.lower()
    domain = domain.replace(".", "").replace("-", "")
    if len(domain) == 0:
        return 0
    counts = Counter(domain)
    probs = [c / len(domain) for c in counts.values()]
    entropy = -sum(p * math.log2(p) for p in probs)
    return 1 if entropy > threshold else 0

# 36. shortening_service - done
def shortening_service(full_url):
    return 1 if re.search(
        r'bit\.ly|tinyurl\.com|t\.co|ow\.ly|is\.gd|tiny\.cc|t\.ly|cutt\.ly|rebrand\.ly|'
        r'short\.io|bl\.ink|t2m\.io|s\.id|singkat\.in|goolink\.id|'
        r'adf\.ly|bc\.vc|v\.gd|lnkd\.in|qr\.ae', # https://en.wikipedia.org/wiki/URL_shortening
        full_url 
    ) else 0

# 37. suspicious_extension - done
def path_extension(path):
    suspicious_ext = (
        r"\.(zip|exe|php|aspx|jsp|apk)$"
    )
    return 1 if re.search(suspicious_ext, path.lower()) else 0

# 38. word_count - done
def length_word_raw(words_raw):
    return len(words_raw)

# 39. char_repeat - done
def char_repeat(words_raw):
    def all_same(s): return all(c == s[0] for c in s)
    total = 0
    for w in words_raw:
        for n in [2, 3, 4, 5]:
            for i in range(len(w) - n + 1):
                if all_same(w[i:i+n]):
                    total += 1
    return total

# 40. shortest word url - done
def shortest_word_url(words_raw):
    return min((len(w) for w in words_raw), default=0)

# 41. longest word url - done
def longest_word_url(words_raw):
    return max((len(w) for w in words_raw), default=0)

# 42. average word url - done
def avg_word_url(words_raw):
    return sum(len(w) for w in words_raw) / len(words_raw) if words_raw else 0

# 43. shortest word host - done
def shortest_word_host(words_host):
    return min((len(w) for w in words_host), default=0)

# 44. longest word host - done
def longest_word_host(words_host):
    return max((len(w) for w in words_host), default=0)

# 45. average word host - done
def avg_word_host(words_host):
    return sum(len(w) for w in words_host) / len(words_host) if words_host else 0

# 46. shortest word path - done
def shortest_word_path(words_path):
    words = [w for w in words_path if w]
    return min((len(w) for w in words), default=0)

# 47. longest word path - done
def longest_word_path(words_path):
    return max((len(w) for w in words_path), default=0)

# 48. average word path - done
def avg_word_path(words_path):
    return sum(len(w) for w in words_path) / len(words_path) if words_path else 0

# 49. phish_hints - done
def phish_hints(path):
    return sum(path.lower().count(h) for h in HINTS)

# 50. domain in brand - done 
def get_root_domain(url):
    extracted = tldextract.extract(url)
    return extracted.domain.lower()

def domain_in_brand(root):
    for b in allbrand:
        if root == b.lower().strip():
            return 1
    return 0

# 51. domain in brand - done
def domain_in_brand1(root):
    for b in allbrand:
        brand = b.lower().strip()
        dist = Levenshtein.distance(root, brand)
        if 0 < dist <= 2:
            return 1
    return 0

# 52. brand in subdomain - done
def brand_in_subdomain(subdomain, root_domain):
    sub = subdomain.lower()
    root = root_domain.lower()

    for b in allbrand:
        brand = b.lower().strip()
        if brand in sub and brand != root:
            return 1
    return 0

# 53. brand in path - done
def brand_in_path(root, path):
    for b in allbrand:
        if b.lower() in path.lower() and b.lower() != root:
            return 1
    return 0

# 54. suspicious_tld - done
suspecious_tlds = [ 
    'top', 'xin', 'xyz', 'bond', 'vip', 'info', 'online', 
    'ru', 'pro', 'cfd', 'sbs', 'cn', 'cc', 'shop', 'site',  
    'icu', 'ren', 'link', 'pe', 'go.id', 'website', 'mx', 'media', # https://www.spamhaus.org/reputation-statistics/ 

    'sx', 'cm', 'ee', 'fw', 'cx', 'ws', 'im', 'la', 'li', 'ng', 'so', 'me', 'top', 
    'eu', 'tr', 'io', 'ro', 'pl', 'ua', 'mx', 'lv', 'ae', 'lt', 'cz', 'de', 'pk',
    'pt', 'es', 'at', 'ke', 'gp', 'date', 'icu', 'online', 'zip' # https://www.broadcom.com/support/security-center/protection-bulletin/top-tld-domains-used-in-tepco-phish-emails
]

def suspecious_tld(tld):
    return 1 if tld in suspecious_tlds else 0

# 55. statistical_report - done
def statistical_report(full_url, domain):
    url_match = re.search(
        r'at\.ua|usa\.cc|pe\.hu|esy\.es|hol\.es|myjino\.ru|ow\.ly',
        full_url
    )
    try:
        ip = socket.gethostbyname(domain)
        ip_match = re.search(r'10\.10\.10\.10|192\.168', ip)
        return 1 if url_match or ip_match else 0
    except:
        return 2
    
# helper
def get_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return ""

def fetch_page(url):
    try:
        r = requests.get(url, timeout=5)

        # kalau gagal status code
        if r.status_code != 200:
            return None, None

        content_type = r.headers.get("Content-Type", "").lower()

        # hanya proses text/html
        if "text/html" not in content_type:
            return None, None

        soup = BeautifulSoup(r.text, "html.parser")
        return r, soup

    except:
        return None, None

def classify_link(href, domain):
    href = href.lower()
    if href in ["", "#", "javascript:void(0)"]:
        return "null"
    elif domain in href:
        return "internal"
    else:
        return "external"

def extract_links(soup, domain):
    Href = {'internals': [], 'externals': [], 'null': []}
    Link = {'internals': [], 'externals': [], 'null': []}
    Media = {'internals': [], 'externals': [], 'null': []}
    Form = {'internals': [], 'externals': [], 'null': []}
    CSS = {'internals': [], 'externals': [], 'null': []}
    Favicon = {'internals': [], 'externals': [], 'null': []}

    for a in soup.find_all("a", href=True):
        c = classify_link(a['href'], domain)
        if c == "internal":
            Href['internals'].append(a['href'])
        elif c == "external":
            Href['externals'].append(a['href'])
        else:
            Href['null'].append(a['href'])

    for link in soup.find_all("link", href=True):
        c = classify_link(link['href'], domain)
        if c == "internal":
            Link['internals'].append(link['href'])
        elif c == "external":
            Link['externals'].append(link['href'])
        else:
            Link['null'].append(link['href'])

    for tag in soup.find_all(["img", "audio", "video"]):
        src = tag.get("src", "")
        c = classify_link(src, domain)
        if c == "internal":
            Media['internals'].append(src)
        elif c == "external":
            Media['externals'].append(src)
        else:
            Media['null'].append(src)

    for form in soup.find_all("form", action=True):
        c = classify_link(form['action'], domain)
        if c == "internal":
            Form['internals'].append(form['action'])
        elif c == "external":
            Form['externals'].append(form['action'])
        else:
            Form['null'].append(form['action'])

    for css in soup.find_all("link", rel="stylesheet", href=True):
        c = classify_link(css['href'], domain)
        if c == "internal":
            CSS['internals'].append(css['href'])
        elif c == "external":
            CSS['externals'].append(css['href'])
        else:
            CSS['null'].append(css['href'])

    for icon in soup.find_all("link", rel=lambda x: x and "icon" in x.lower(), href=True):
        c = classify_link(icon['href'], domain)
        if c == "internal":
            Favicon['internals'].append(icon['href'])
        elif c == "external":
            Favicon['externals'].append(icon['href'])
        else:
            Favicon['null'].append(icon['href'])

    return Href, Link, Media, Form, CSS, Favicon

# CONTENT BASED 

# 1. num hyperlink - done
def num_hyperlinks(Href, Link, Media, Form, CSS, Favicon):
    total = 0
    total += len(Href['internals']) + len(Href['externals']) + len(Href['null'])
    total += len(Link['internals']) + len(Link['externals']) + len(Link['null'])
    total += len(Media['internals']) + len(Media['externals']) + len(Media['null'])
    total += len(Form['internals']) + len(Form['externals']) + len(Form['null'])
    total += len(CSS['internals']) + len(CSS['externals']) + len(CSS['null'])
    total += len(Favicon['internals']) + len(Favicon['externals']) + len(Favicon['null'])
    return total

# total - done
def h_total(Href, Link, Media, Form, CSS, Favicon):
    return num_hyperlinks(Href, Link, Media, Form, CSS, Favicon)

# 2. internal link ratio - done
def internal_link_ratio(Href, Link, Media, Form, CSS, Favicon):
    internal = (
        len(Href['internals']) + len(Link['internals']) +
        len(Media['internals']) + len(Form['internals']) +
        len(CSS['internals']) + len(Favicon['internals'])
    )
    total = h_total(Href, Link, Media, Form, CSS, Favicon)
    return internal / total if total > 0 else 0

# 3. external link ratio - done
def external_link_ratio(Href, Link, Media, Form, CSS, Favicon):
    external = (
        len(Href['externals']) + len(Link['externals']) +
        len(Media['externals']) + len(Form['externals']) +
        len(CSS['externals']) + len(Favicon['externals'])
    )
    total = h_total(Href, Link, Media, Form, CSS, Favicon)
    return external / total if total > 0 else 0

# 4. null link ratio - done
def null_link_ratio(Href, Link, Media, Form, CSS, Favicon):
    nulls = (
        len(Href['null']) + len(Link['null']) +
        len(Media['null']) + len(Form['null']) +
        len(CSS['null']) + len(Favicon['null'])
    )
    total = h_total(Href, Link, Media, Form, CSS, Favicon)
    return nulls / total if total > 0 else 0

# 5. external css - done
def num_external_css(CSS):
    return len(CSS['externals'])

# 6. login form abnormal - done
def login_form_abnormal(Form, domain):
    if len(Form['externals']) > 0 or len(Form['null']) > 0:
        return 1
    for action in Form['internals']:
        if domain not in action:
            return 1
    return 0

# 7. external favicon - done
def external_favicon(Favicon, domain):
    if len(Favicon['externals']) > 0:
        return 1
    return 0


# 8. link tag ratio - done
def link_tag_ratio(Link, Href):
    total = (len(Href['internals']) + len(Href['externals']) + len(Href['null']) +
             len(Link['internals']) + len(Link['externals']) + len(Link['null']))
    internals = len(Link['internals'])
    if total == 0:
        return 0
    return internals / total  

# 9. submit to email - done
def submit_to_email(Form):
    for form in Form['internals'] + Form['externals']:
        if "mailto:" in form or "mail()" in form:
            return 1
    return 0


# 10. internal media ratio - done
def internal_media_ratio(Media):
    internal = len(Media.get('internals', []))
    external = len(Media.get('externals', []))
    total = internal + external
    if total == 0:
        return 0
    return (internal / total) * 100  


# 11. external media ratio - done
def external_media_ratio(Media):
    internal = len(Media.get('internals', []))
    external = len(Media.get('externals', []))
    total = internal + external
    if total == 0:
        return 0
    return (external / total) * 100 

# 12. sfh - done
def sfh(Form):
    if len(Form['null']) > 0 or len(Form['externals']) > 0:
        return 1
    return 0


# 13. invisible iframe - done
def invisible_iframe(soup):
    if soup is None:
        return 0
    for iframe in soup.find_all("iframe"):
        if iframe.get("width") == "0" or iframe.get("height") == "0":
            return 1
    return 0


# 14. popup window - done
def popup_window(content):
    if "window.open" in str(content).lower():
        return 1
    else:
        return 0

# 15. unsafe anchor - done
def unsafe_anchor(Href):
    total = len(Href['internals']) + len(Href['externals']) + len(Href['null'])
    unsafe = 0
    for url in Href['externals'] + Href['null']:
        if url.startswith(("javascript", "mailto", "#")):
            unsafe += 1
    try:
        percentile = unsafe / float(total) * 100
    except ZeroDivisionError:
        return 0
    return percentile

# 16. on mouse
def onmouse(content):
    if 'onmouseover="window.status=' in str(content).lower().replace(" ", ""):
        return 1
    else:
        return 0

# 17. right click disabled
def right_click_disabled(content):
    if 'event.button==2' in str(content).lower().replace(" ", ""):
        return 1
    else:
        return 0

# 18. empty title - done
def empty_title(soup):
    if soup is None:
        return 1
    if soup.title and soup.title.text.strip():
        return 0
    return 1

# 19. domain in title - done
def domain_in_title(domain, soup):
    if soup is None:
        return 1
    if soup.title and domain.lower() in soup.title.text.lower():
        return 0
    return 1

# 20. domain in copyright - done
def domain_in_copyright(domain, content):
    try:
        m = re.search(u'(\N{COPYRIGHT SIGN}|\N{TRADE MARK SIGN}|\N{REGISTERED SIGN})', content)
        if m:
            start = m.span()[0] - 50
            end = m.span()[0] + 50
            snippet = content[start:end]
            if domain.lower() in snippet.lower():
                return 0
            else:
                return 1
        else:
            return 1   
    except:
        return 1

# fungsi load dataset
def load_dataset(file_path):
    df = pd.read_csv(file_path)
    
    if df.columns[0].lower() != 'url':
        url_col = [c for c in df.columns if c.lower() == 'url']
        if url_col:
            url_data = df[url_col[0]]
            df.drop(columns=[url_col[0]], inplace=True)
            df.insert(0, 'url', url_data)
    
    if df.columns[-1].lower() != 'label':
        label_col = [c for c in df.columns if c.lower() == 'label']
        if label_col:
            label_data = df[label_col[0]]
            df.drop(columns=[label_col[0]], inplace=True)
            df['label'] = label_data
    
    data = list(zip(df['url'], df['label']))
    return data

# ekstrak fitur dari url
def extract_features(url):
    scheme, full_url, base_url, hostname, path, query, words_raw, words_host, words_path = parse_url(url)
    domain = get_domain(url)

    resp, soup = fetch_page(url)
    if soup is None:
        return None
    
    root = get_root_domain(url)

    # default supaya tidak undefined
    Href = {'internals': [], 'externals': [], 'null': []}
    Link = {'internals': [], 'externals': [], 'null': []}
    Media = {'internals': [], 'externals': [], 'null': []}
    Form = {'internals': [], 'externals': [], 'null': []}
    CSS = {'internals': [], 'externals': [], 'null': []}
    Favicon = {'internals': [], 'externals': [], 'null': []}
    content = ""

    if soup is not None:
        Href, Link, Media, Form, CSS, Favicon = extract_links(soup, domain)
        content = resp.text if resp else ""

    features = {}

    # 1–10
    features['url_length'] = url_length(full_url)                       # 1
    features['hostname_length'] = hostname_length(hostname)             # 2
    features['has_ip'] = having_ip_address(full_url)                    # 3
    features['count_dot'] = count_dot(hostname)                         # 4
    features['count_hyphen'] = count_hyphen(base_url)                   # 5
    features['count_at'] = count_at(base_url)                           # 6
    features['count_question'] = count_question(full_url)               # 7
    features['count_ampersand'] = count_ampersand(full_url)             # 8
    features['count_pipe'] = count_pipe(full_url)                       # 9
    features['count_equal'] = count_equal(full_url)                     # 10

    # 11–20
    features['count_underscore'] = count_underscore(base_url)           # 11
    features['count_tilde'] = count_tilde(full_url)                     # 12
    features['count_percent'] = count_percent(full_url)                 # 13
    features['count_slash'] = count_slash(full_url)                     # 14
    features['count_asterisk'] = count_asterisk(full_url)               # 15
    features['count_colon'] = count_colon(full_url)                     # 16
    features['count_comma'] = count_comma(base_url)                     # 17
    features['count_semicolon'] = count_semicolon(full_url)             # 18
    features['count_dollar'] = count_dollar(base_url)                   # 19
    features['count_space'] = count_space(full_url)                     # 20

    # 21–30
    features['count_www'] = count_www(words_raw)                         # 21
    features['count_com'] = count_com(words_raw)                         # 22
    features['count_http'] = count_http_token(path)                      # 23
    features['count_double_slash'] = count_double_slash(full_url)        # 24
    features['has_https'] = https_token(scheme)                          # 25
    features['digit_ratio_url'] = digit_ratio_url(full_url)              # 26
    features['digit_ratio_host'] = ratio_digits(hostname)                # 27
    features['has_punycode'] = punycode(full_url)                        # 28
    features['has_port'] = port(full_url)                                # 29

    tld = hostname.split('.')[-1] if '.' in hostname else ''             # 30
    subdomain = '.'.join(hostname.split('.')[:-2]) if hostname.count('.') >= 2 else ''

    # 31-37
    features['tld_in_path'] = tld_in_path(tld, path)                     # 31
    features['tld_in_subdomain'] = tld_in_subdomain(tld, subdomain)      # 32
    features['abnormal_subdomain'] = abnormal_subdomain(full_url)        # 33
    features['subdomain_count'] = count_subdomain(hostname)              # 34
    features['prefix_suffix'] = prefix_suffix(full_url)                  # 35
    features['random_domain'] = random_domain(hostname)                  # 35
    features['shortening_service'] = shortening_service(full_url)        # 36
    features['suspicious_extension'] = path_extension(path)              # 37

    # 38-48
    features['word_count'] = length_word_raw(words_raw)                  # 38
    features['char_repeat'] = char_repeat(words_raw)                     # 39
    features['shortest_word_url'] = shortest_word_url(words_raw)         # 40
    features['shortest_word_host'] = shortest_word_host(words_host)      # 41
    features['shortest_word_path'] = shortest_word_path(words_path)      # 42
    features['longest_word_url'] = longest_word_url(words_raw)           # 43
    features['longest_word_host'] = longest_word_host(words_host)        # 44
    features['longest_word_path'] = longest_word_path(words_path)        # 45
    features['avg_word_url'] = avg_word_url(words_raw)                   # 46
    features['avg_word_host'] = avg_word_host(words_host)                # 47
    features['avg_word_path'] = avg_word_path(words_path)                # 48

    # 49-55
    features['phish_hints'] = phish_hints(path)                               # 49
    features['domain_in_brand'] = domain_in_brand(root)                       # 50
    features['domain_in_brand1'] = domain_in_brand1(root)                     # 51
    features['brand_in_subdomain'] = brand_in_subdomain(subdomain, root)      # 52
    features['brand_in_path'] = brand_in_path(hostname, path)                 # 53
    features['suspecious_tld'] = suspecious_tld(tld)                          # 54
    features['statistical_report'] = statistical_report(full_url, hostname)   # 55

    # 1-20
    features['num_hyperlinks'] = num_hyperlinks(Href, Link, Media, Form, CSS, Favicon)
    features['internal_link_ratio'] = internal_link_ratio(Href, Link, Media, Form, CSS, Favicon)
    features['external_link_ratio'] = external_link_ratio(Href, Link, Media, Form, CSS, Favicon)
    features['null_link_ratio'] = null_link_ratio(Href, Link, Media, Form, CSS, Favicon)
    features['num_external_css'] = num_external_css(CSS)
    features['login_form_abnormal'] = login_form_abnormal(Form, domain)
    features['external_favicon'] = external_favicon(Favicon, domain)
    features['link_tag_ratio'] = link_tag_ratio(Link, Href)
    features['submit_to_email'] = submit_to_email(Form)
    features['internal_media_ratio'] = internal_media_ratio(Media)
    features['external_media_ratio'] = external_media_ratio(Media)
    features['sfh'] = sfh(Form)
    features['invisible_iframe'] = invisible_iframe(soup)
    features['popup_window'] = popup_window(content)
    features['unsafe_anchor'] = unsafe_anchor(Href)
    features['onmouse'] = onmouse(content)
    features['right_click_disabled'] = right_click_disabled(content)
    features['empty_title'] = empty_title(soup)
    features['domain_in_title'] = domain_in_title(domain, soup)
    features['domain_in_copyright'] = domain_in_copyright(domain, content)

    return features

# fungsi proses dataset dan ekstrak fitur 
def process_dataset_realtime(file_path, output_path):

    if os.path.exists(output_path):
        os.remove(output_path)

    data = load_dataset(file_path)

    for i, (url, label) in enumerate(data, start=1):

        try:
            feats = extract_features(url)

            if feats is None:
                print(f"Skip gagal fetch: {url}")
                continue

        except Exception as e:
            print(f"Error di {url}: {e}")
            continue

        feats['url'] = url
        feats['label'] = label

        df_row = pd.DataFrame([feats])

        # kolom
        cols = df_row.columns.tolist()
        cols.remove('url')
        cols.remove('label')
        cols = ['url'] + cols + ['label']
        df_row = df_row[cols]

        file_exists = os.path.exists(output_path)

        df_row.to_csv(
            output_path,
            mode='a',
            index=False,
            header=not file_exists
        )

        print(f"URL ke-{i} langsung masuk CSV")

    print("SELESAI PROSES")


# main program
if __name__ == "__main__":

    dataset_path = r"D:\skripsi\dataset\new_dataset_legitimate_2_clean_vers.csv"
    output_path = r"D:\skripsi\dataset\new_dataset_legitimate_3_clean_vers2.csv"

    print("Mulai proses ekstraksi fitur realtime...")
    process_dataset_realtime(dataset_path, output_path)

    print(f"File CSV berhasil disimpan: {output_path}")
    print("SELESAI")