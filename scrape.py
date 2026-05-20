import os
import re
import requests
from concurrent.futures import ThreadPoolExecutor

SAVE_PATH = "/root/methods/proxy.txt"

RAW_URLS = [

    # MAIN
"https://raw.githubusercontent.com/aidilnugrho-pixel/methods/refs/heads/main/proxy.txt",
 "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/http/data.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/HTTPS.txt",
    "https://raw.githubusercontent.com/databay-labs/free-proxy-list/refs/heads/master/http.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/refs/heads/master/generated/http_proxies.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/refs/heads/main/proxies/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/refs/heads/master/http.txt",
    "https://raw.githubusercontent.com/watchttvv/free-proxy-list/refs/heads/main/proxy.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/r00tee/Proxy-List/refs/heads/main/Https.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/refs/heads/master/http.txt",
    "https://raw.githubusercontent.com/themiralay/Proxy-List-World/refs/heads/master/data.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/refs/heads/main/http.txt",
    "https://raw.githubusercontent.com/dpangestuw/Free-Proxy/refs/heads/main/http_proxies.txt",
    # COUNTRIES A - Z LENGKAP
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Afghanistan.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Albania.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Algeria.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Andorra.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Angola.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Anguilla.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Antigua_and_Barbuda.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Argentina.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Armenia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Aruba.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Australia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Austria.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Azerbaijan.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Bahamas.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Bahrain.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Bangladesh.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Barbados.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Belarus.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Belgium.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Belize.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Benin.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Bhutan.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Bolivia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Bosnia_and_Herzegovina.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Botswana.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Brazil.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/British_Virgin_Islands.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Brunei.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Bulgaria.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Burkina_Faso.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Burundi.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Cambodia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Cameroon.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Canada.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Cayman_Islands.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Chad.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Chile.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/China.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Colombia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Congo_Republic.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Cook_Islands.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Costa_Rica.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Croatia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Cuba.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Curaçao.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Cyprus.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Czechia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/DR_Congo.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Denmark.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Djibouti.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Dominican_Republic.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Ecuador.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Egypt.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/El_Salvador.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Equatorial_Guinea.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Estonia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Eswatini.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Ethiopia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Finland.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/France.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/French_Polynesia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/French_Southern_Territories.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Gabon.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Gambia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Georgia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Germany.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Ghana.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Gibraltar.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Greece.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Greenland.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Guadeloupe.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Guam.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Guatemala.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Guinea.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Guyana.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Haiti.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Honduras.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Hong_Kong.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Hungary.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Iceland.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/India.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Indonesia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Iran.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Iraq.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Ireland.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Israel.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Italy.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Ivory_Coast.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Jamaica.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Japan.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Jordan.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Kazakhstan.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Kenya.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Kosovo.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Kuwait.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Kyrgyzstan.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Laos.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Latvia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Lebanon.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Lesotho.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Liberia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Libya.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Lithuania.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Luxembourg.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Macao.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Madagascar.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Malawi.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Malaysia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Maldives.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Mali.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Malta.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Martinique.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Mauritania.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Mauritius.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Mayotte.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Mexico.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Moldova.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Monaco.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Mongolia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Montenegro.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Morocco.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Mozambique.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Myanmar.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Namibia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Nepal.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/New_Caledonia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/New_Zealand.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Nigeria.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Norfolk_Island.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/North_Macedonia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Norway.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Oman.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Pakistan.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Palestine.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Panama.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Papua_New_Guinea.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Paraguay.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Peru.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Philippines.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Poland.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Portugal.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Puerto_Rico.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Qatar.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Romania.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Russia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Rwanda.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Saint_Martin.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Samoa.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Saudi_Arabia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Senegal.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Serbia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Seychelles.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Sierra_Leone.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Singapore.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Sint_Maarten.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Slovakia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Slovenia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Solomon_Islands.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Somalia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/South_Africa.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/South_Korea.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/South_Sudan.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Spain.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Sri_Lanka.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/St_Vincent_and_Grenadines.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Sudan.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Suriname.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Sweden.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Switzerland.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Syria.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Taiwan.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Tajikistan.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Tanzania.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Thailand.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/The_Netherlands.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Timor-Leste.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Togo.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Trinidad_and_Tobago.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Tunisia.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Turkmenistan.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Tuvalu.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Türkiye.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/US_Virgin_Islands.txt",
    "https://raw.githubusercontent.com/SoliSpirit/proxy-list/refs/heads/main/Countries/http/Uganda.txt"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

PROXY_REGEX = re.compile(
    r"(?:https?:\/\/|socks4:\/\/|socks5:\/\/)?"
    r"((?:\d{1,3}\.){3}\d{1,3}:\d{1,5})"
)

def fetch(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            print(f"[OK] {url}")
            return r.text
    except:
        pass
    return ""

def clean(content):
    proxies = set()

    matches = PROXY_REGEX.findall(content)

    for proxy in matches:
        try:
            ip, port = proxy.split(":")
            port = int(port)

            if not (1 <= port <= 65535):
                continue

            octets = ip.split(".")
            if len(octets) != 4:
                continue

            if all(0 <= int(o) <= 255 for o in octets):
                proxies.add(f"{ip}:{port}")

        except:
            continue

    return proxies

def main():
    all_proxies = set()

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(fetch, RAW_URLS)

    for content in results:
        all_proxies.update(clean(content))

    final = sorted(all_proxies)

    os.makedirs("/root/methods", exist_ok=True)

    with open(SAVE_PATH, "w") as f:
        f.write("\n".join(final))

    print(f"\nSaved {len(final)} proxies -> {SAVE_PATH}")

if __name__ == "__main__":
    main()