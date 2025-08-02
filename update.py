import requests
from pathlib import Path
from datetime import datetime, timedelta
from zlib import adler32

RETAIN_DAYS = 30
DUPLICATE_CHECK_DEPTH = 6

BLOCKLIST_LIST = [
    {'name':'binarydefense','url':'https://www.binarydefense.com/banlist.txt'},
    {'name':'blocklistde','url':'https://lists.blocklist.de/lists/all.txt'},
    {'name':'cinsarmy','url':'https://cinsarmy.com/list/ci-badguys.txt'},
    {'name':'dshield','url':'https://isc.sans.edu/block.txt'},
    {'name':'greensnow','url':'https://blocklist.greensnow.co/greensnow.txt'},
    {'name':'spamhaus_drop_asn','url':'https://www.spamhaus.org/drop/asndrop.json'},
    {'name':'turris','url':'https://view.sentinel.turris.cz/greylist-data/greylist-latest.csv'},
]

def prune(database_dir: Path):
    datetime_now = datetime.utcnow()
    for file in database_dir.iterdir():
        elapsed = datetime_now - datetime.strptime(file.stem, '%Y%m%d.%H%M%S')
        if elapsed > timedelta(days=RETAIN_DAYS, hours=2):
            file.unlink()

def check_mtime(database_dir: Path, url: str):
    latestfile = None
    for file in database_dir.iterdir():
        if latestfile is None:
            latestfile = file
            continue
        if datetime.strptime(file.stem, '%Y%m%d.%H%M%S') > datetime.strptime(latestfile.stem, '%Y%m%d.%H%M%S'):
            latestfile = file
    if latestfile is None:
        return True
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0','Accept-Encoding': 'gzip, deflate'}
    try:
        response = requests.head(url, headers=headers)
        response.raise_for_status()
    except Exception as e:
        print(f'{e}')
        return False
    remote_mtime = datetime.strptime(response.headers['Last-Modified'], '%a, %d %b %Y %H:%M:%S %Z')
    local_mtime = datetime.strptime(latestfile.stem, '%Y%m%d.%H%M%S')
    if local_mtime > remote_mtime:
        return False
    return True

def fetch(url: str) -> str:
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0','Accept-Encoding': 'gzip, deflate'}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except Exception as e:
        print(f'{e}')
        return None
    return response.text

def convert(blocklist_name: str, fetch_data: str) -> str:
    result_list = list()
    for line in fetch_data.splitlines():
        if len(line) == 0:
            continue
        if line.startswith('#'):
            continue
        if '.' not in line and ':' not in line:
            continue
        match blocklist_name:
            case 'bruteforceblocker':
                result_list.append(line.split('\t')[0])
            case 'dshield':
                elements = line.split('\t')
                result_list.append(f'{elements[0]}/{elements[2]}')
            case 'turris':
                result_list.append(line.split(',')[0])
            case blocklist_name if blocklist_name.startswith('spamhaus_drop'):
                if 'metadata' in line:
                    continue
                result_list.append(line.split(',"')[0].split('":')[1].strip('"'))
            case _:
                result_list.append(line)
    result_list.sort()
    return '\n'.join(result_list)

def save(database_dir: Path, convert_data: str):
    checksum = adler32(convert_data.encode())
    latestfile_list = [None] * DUPLICATE_CHECK_DEPTH
    for file in database_dir.iterdir():
        if latestfile_list[0] is None:
            latestfile_list[0] = file
            continue
        if datetime.strptime(file.stem, '%Y%m%d.%H%M%S') > datetime.strptime(latestfile_list[0].stem, '%Y%m%d.%H%M%S'):
            latestfile_list = [file] + latestfile_list[:-1]
    file_new = database_dir / f"{datetime.utcnow().strftime('%Y%m%d.%H%M%S')}.txt"
    for latestfile in latestfile_list:
        if latestfile is None:
            continue
        if checksum == adler32(latestfile.read_text().encode()):
            latestfile.touch()
            latestfile.rename(file_new)
            return False
    file_new.write_text(convert_data)
    return True

def generate(database_dir: Path, lists_dir: Path, days: int):
    ipset = set()
    datetime_now = datetime.utcnow()
    for file in database_dir.iterdir():
        elapsed = datetime_now - datetime.strptime(file.stem, '%Y%m%d.%H%M%S')
        if elapsed > timedelta(days=days, hours=2):
            continue
        for line in file.read_text().splitlines():
            ipset.add(line)
    Path(lists_dir / f'{days}d.txt').write_text('\n'.join(ipset))

def generate_latest(database_dir: Path, lists_dir: Path):
    latestfile = None
    for file in database_dir.iterdir():
        if latestfile is None:
            latestfile = file
            continue
        if datetime.strptime(file.stem, '%Y%m%d.%H%M%S') > datetime.strptime(latestfile.stem, '%Y%m%d.%H%M%S'):
            latestfile = file
    Path(lists_dir / 'latest.txt').write_text(latestfile.read_text())

def generate_asn(database_dir: Path, lists_dir: Path):
    latestfile = None
    for file in database_dir.iterdir():
        if latestfile is None:
            latestfile = file
            continue
        if datetime.strptime(file.stem, '%Y%m%d.%H%M%S') > datetime.strptime(latestfile.stem, '%Y%m%d.%H%M%S'):
            latestfile = file
    network_list = list()
    for asn in latestfile.read_text().splitlines():
        url = f'https://raw.githubusercontent.com/ipverse/asn-ip/master/as/{asn}/aggregated.json'
        try:
            response = requests.get(url)
            response.raise_for_status()
        except Exception as e:
            print(f'{e}')
            continue
        data = response.json()
        if len(data['subnets']['ipv4']) != 0:
            network_list.extend(data['subnets']['ipv4'])
        if len(data['subnets']['ipv6']) != 0:
            network_list.extend(data['subnets']['ipv6'])
    Path(lists_dir / f'latest_expand.txt').write_text('\n'.join(network_list))

def main():
    for blocklist in BLOCKLIST_LIST:
        print(f"start: {blocklist['name']}")
        database_dir = Path(f"database/{blocklist['name']}")
        database_dir.mkdir(parents=True, exist_ok=True)
        lists_dir = Path(f"lists/{blocklist['name']}")
        lists_dir.mkdir(parents=True, exist_ok=True)

        prune(database_dir)
        if not check_mtime(database_dir, blocklist['url']):
            print(f"end:   {blocklist['name']}, no update")
            continue
        fetch_data = fetch(blocklist['url'])
        if fetch_data is None:
            print(f"end:   {blocklist['name']}, fetch failed")
            continue
        convert_data = convert(blocklist['name'], fetch_data)
        if not save(database_dir, convert_data):
            print(f"end:   {blocklist['name']}, touch filename")
            continue

        if blocklist['name'] == 'spamhaus_drop_asn':
            generate_asn(database_dir, lists_dir)

        generate(database_dir, lists_dir, 30)
        generate(database_dir, lists_dir, 14)
        generate(database_dir, lists_dir, 7)
        generate(database_dir, lists_dir, 3)
        generate(database_dir, lists_dir, 1)
        generate_latest(database_dir, lists_dir)
        print(f"end:   {blocklist['name']}")

if __name__ == "__main__":
    main()
