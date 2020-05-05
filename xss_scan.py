#! /usr/bin/env python

#Desenvolvedor: Victor Pegoraro

#Call libs
import argparse, socket, sys, requests, json, time
from urllib.parse import urlparse, urljoin
import colorama
from bs4 import BeautifulSoup as bs
from tld import get_fld
import urllib.request

# init the colorama module
colorama.init()
GREEN  = colorama.Fore.GREEN
GRAY   = colorama.Fore.LIGHTBLACK_EX
RESET  = colorama.Fore.RESET
CYAN   = colorama.Fore.CYAN
RED    = colorama.Fore.RED
YELLOW = colorama.Fore.YELLOW

#Start print
start = """
        ##################################
        ##                              ##
        ##        XSS Scan Tool         ##
        ##                              ##
        ##  Developer: Victor Pegoraro  ##
        ## V1.0            433 payloads ##
        ##################################
        """

#Header report
header = """
        XSS Scan Tool
        """

#Set arguments
des = """ 
    Description: security tool for XSS(Cross site script) and crawl site
    --------------------------------------------------------------------
    """
parser = argparse.ArgumentParser(description=des)
parser.add_argument("url", help="Define the url EX: https://www.yourwebsite.com " , type=str)
parser.add_argument("-c", "--crawl", action="store", dest='crawl' , type=int, default= 3 , help="Crawl pages, set number of pages" , )
parser.add_argument("-a", "--attack", action="store_true", help="Test payloads on web page")
parser.add_argument("-r", "--report" ,action="store_true", help="Write the results in a file: report.txt ")
args = parser.parse_args()


#Check valid url
def is_valid(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

# Function to get the top level domain
def get_domain_name ( url ):
    domain_name = get_fld(url)
    return domain_name

#Storage all urls
urls = set()

# initialize the set of links (unique links)
internal_urls = set()
external_urls = set()

#Checks whether url is a valid URL
def is_valid(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)


#return al urls from page
def get_all_website_links(url):

    # domain name of the URL without the protocol
    domain_name = urlparse(url).netloc
    #Request page
    soup = bs(requests.get(url).content, "html.parser")

    for a_tag in soup.findAll("a"): #Find all 'a' tag from page
        href = a_tag.attrs.get("href")#Get atribute from tag

        if href == "" or href is None:
            # href empty tag
            continue

        # join the URL if it's relative (not absolute link)
        href = urljoin(url, href)
        parsed_href = urlparse(href)
        # remove URL GET parameters, URL fragments, etc.
        href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path

        # not a valid URL
        if not is_valid(href):
            continue

        # already in the set
        if href in internal_urls:
            continue

        #Check domain name in link
        if domain_name not in href:
            # external link
            if href not in external_urls:
                print(f"{GRAY}[!] External link: {href}{RESET}")
                external_urls.add(href)
                urls.add(href)
            continue

        #Internal links
        print(f"{GREEN}[*] Internal link: {href}{RESET}")
        urls.add(href)
        internal_urls.add(href)

    return urls


#Number of urls visited so far will be stored here
total_urls_visited = 0

#Crawl page
def crawl(url, max_urls):

    global total_urls_visited #Call varieble
    total_urls_visited += 1 
    links = get_all_website_links(url) #Find links in page
    for link in links:
        #Verify if crawl max urls
        if total_urls_visited > max_urls:
            print(f"{YELLOW}[!] " + str(max_urls) + f" was tested !{RESET}" )
            #Show all informations found
            show_info()
            #Write report if set
            if args.report:
                print(f"{GREEN}[+] Reporting...{RESET}")
                report = open("report.txt", "w") #Create document 
                report.write(header) #Write header in document
                report.write("\n")
                report.write("Crawl Report")
                report.write("\n")
                report.write("=================================================")
                report.write("\n [!] Links founds: " + str(len(urls)))
                report.write("\n [+] Internal links: " + str(len(internal_urls)))
                report.write("\n [+] External links: " + str(len(external_urls)))
                report.write("\n")
                report.write("\n")
                for link in links :
                    # write links in report
                    report.write(link)
                    report.write("\n")

                report.close()#Close document
            #Close program
                sys.exit()
            sys.exit()

        #Keep crawling 
        crawl(link, max_urls)


#Return forms from url
def get_all_forms(url):
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

#Extracts all possible useful information about an HTML `form`
def get_form_details(form):
    details = {}
    #Get the form action (target url)
    action = form.attrs.get("action")

    #Get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get")

    #Get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    
    #Put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

#Submits a form given in 'form_details'
def submit_form(form_details, url, value):
    #Params:
    #    form_details (list): a dictionary that contain form information
    #    url (str): the original URL that contain that form
    #    value (str): this will be replaced to all text and search inputs
    #Returns the HTTP Response after form submission

    #Construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])

    #Get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        #Replace all text and search values with 'value'
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            #If input name and value are not None, 
            # then add them to the data of form submission
            data[input_name] = input_value

    #Send request
    if form_details["method"] == "post":
        # Post request 
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)

#Test payloads in url forms
def scan_xss(url):
    #Get all the forms from the URL
    forms = get_all_forms(url)

    #Verify found forms
    if(len(forms) > 0):
        #Show found forms
        print(f"{GREEN}[+] Detected {len(forms)} forms on {url}{RESET}")    
        print(f"{CYAN}[#] Scan in progress, wait... {RESET}")
    else:
        #Finish program if no find forms tag
        print(f"{YELLOW}[!] This page no have forms tags... {RESET}")
        sys.exit()
    
    #Load payloads
    js_script = open("payloads.txt", "r", encoding="utf8")
    #Insert payloads in list
    lines = list(js_script)
    #Create constants
    vul_forms = []
    exploits = []
    #Returning value
    is_vulnerable = False
    #Test all forms
    f = 1
    for form in forms:
        form_details = get_form_details(form)
        print(f"{CYAN}[+] Testing form " + str(f))
        f += 1
        for script in lines:
            #Insert script in page
            try:
                content = submit_form(form_details, url, script).content.decode()
                if script in content:
                    print(f"{YELLOW}[!] Script injected: " + script, end='\r')
                    lista = form_details.get('inputs')
                    name = lista[0]
                    exploits.append(script)
                    is_vulnerable = True
                    if name.get("name") not in vul_forms:
                        vul_forms.append(name.get('name'))
            #If lost connection
            except requests.exceptions.ConnectionError:
                print(f"{RED}[-] Connection fail")
                break
            #If press to stop program
            except KeyboardInterrupt:
                print(f"{RED}[+] Stop inject")
                break
            #Something else
            except:
                print(f"{RED}[-] Some error !!")
                break

    #Show if find some injected script on page 
    if is_vulnerable:
        print(f"{CYAN}=================================================")
        print(f"{RED}[!] XSS Detected on {url} {RESET} ")
        for form in vul_forms:
            print(f"{YELLOW}[!] Form name " + form + " is vulnerable")
        print(f"{YELLOW}[!] Are " + str(len(exploits)) + " payloads for " + url)
        print(f'{CYAN}[#]Time taken:', time.time() - startTime , " seconds")

    #If can't inject any script
    else:
        print(f"{GREEN}[+] Page is safe ! {RESET}")

    #Close payloads documents 
    js_script.close

    #If report is set write a document
    if args.report:
        print(f"{GREEN}[+] Reporting...{RESET}")
        report = open("report.txt", "w") #create document
        report.write(header) #Write header in document
        report.write("\n")
        report.write("Cross site Script injection report \n")
        report.write("[!] XSS Detected on " + url + "\n")
        report.write("Payloads: \n ")
        report.write("\n")
        for e in exploits:
            #Write scripts injected in page 
            report.write(str(e) + "\n")

        report.close() #Close document
    sys.exit() #Exit program


def show_info():
    #Show infomation
    print(f"{CYAN}=================================================")
    print(f"{YELLOW}[!] Links founds: " + str(len(urls)))
    print(f"{GREEN}[+] Internal links: " + str(len(internal_urls)))
    print(f"{CYAN}[+] External links: " + str(len(external_urls)))
    print(f'{CYAN}[#]Time taken:', time.time() - startTime)



#Start program
print(f"{CYAN}" + start)

#Get arguments

#Attack : -a  or --attack
if args.attack:
    url = args.url
    startTime = time.time()
    scan_xss(args.url)
    sys.exit()

        
        #Crawl : -c  or --crawl
if args.crawl:
    domain = get_fld(args.url)
    startTime = time.time()
    print(f"{GREEN}[+] Start crawl: " + domain +"\n")
    #Crawl page
    crawl(args.url, args.crawl)
