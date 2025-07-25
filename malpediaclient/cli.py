import argparse
import malpediaclient
import pkg_resources
import json
import os
import base64
import sys
from operator import itemgetter
from pathlib import Path

CONFIG_LOCATIONS = [
    # Current directory
    os.path.join(os.curdir, "malpedia.json"),
    os.path.join(os.curdir, ".malpedia.json"),
    # Linux user takes precedence over linux system
    "$HOME/.malpedia.json",
    "/etc/malpedia.json",
    # Windows
    "${APPDATA}\\malpedia\\malpedia.json",
]

def _load_config_and_authenticate(malpedia_client):
    username, password, apitoken = None, None, None
    has_config = False

    # try to find a config in common locations
    for loc in [os.path.expandvars(loc) for loc in CONFIG_LOCATIONS]:
        try:
            with open(loc, "r") as cfg_file:
                cfg = json.load(cfg_file)
                if 'username' in cfg:
                    username = cfg['username']
                if 'password' in cfg:
                    password = cfg['password']
                if 'apitoken' in cfg:
                    apitoken = cfg['apitoken']

                if apitoken or (username and password):
                    has_config = True
                    break
                else:
                    print(f"[!] Found config file \"{loc}\" but it does neither contain an apitoken nor a username and password.")
                    return False
        except json.JSONDecodeError as err:
            print(f"[!] Found config file \"{loc}\" but it does not contain valid JSON: {err.msg}")
            return False
        except IOError:
            # look for the next possible location
            pass

    if not has_config:
        return False

    if apitoken:
        malpedia_client.authenticate_by_token(apitoken)
    elif username and password:
        malpedia_client.authenticate(username, password)
    else:
        return False

    return True

def _printj(result):
    print(json.dumps(result, indent=4))

def _save_file(path, content, is_base64=False):
    if is_base64:
        content = base64.b64decode(content)
    with open(path, 'wb') as f:
        f.write(content)
    print(f"[+] Saved to {path}")

class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write(f'error: {message}\n')
        self.print_help()
        sys.exit(2)

def main():
    parser = MyParser(description='Malpedia API Client v{}'.format(malpediaclient.__version__))
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    subparsers.required = True

    # List families
    list_families_parser = subparsers.add_parser('list_families', help='List all available families')
    list_families_parser.set_defaults(func=list_families_result)

    # List actors
    list_actors_parser = subparsers.add_parser('list_actors', help='List all available actors')
    list_actors_parser.set_defaults(func=list_actors_result)

    # List samples
    list_samples_parser = subparsers.add_parser('list_samples', help='List all samples for a given family')
    list_samples_parser.add_argument('family_id', help='ID of the family')
    list_samples_parser.set_defaults(func=list_samples_result)

    # List YARA
    list_yara_parser = subparsers.add_parser('list_yara', help='List all available YARA rules')
    list_yara_parser.set_defaults(func=list_yara_result)

    # List ApiScout
    list_apiscout_parser = subparsers.add_parser('list_apiscout', help='List all available ApiScout data')
    list_apiscout_parser.set_defaults(func=list_apiscout_results)

    # List ApiScout CSV
    list_apiscout_csv_parser = subparsers.add_parser('list_apiscout_csv', help='Download ApiScout data as CSV')
    list_apiscout_csv_parser.add_argument('destination', help='Path where the CSV file should be stored')
    list_apiscout_csv_parser.set_defaults(func=list_apiscout_results)

    # Get sample raw
    get_sample_raw_parser = subparsers.add_parser('get_sample_raw', help='Download a specific sample')
    get_sample_raw_parser.add_argument('sha256', help='SHA256 hash of the sample')
    get_sample_raw_parser.add_argument('destination', help='Path where the sample should be stored')
    get_sample_raw_parser.set_defaults(func=get_sample_raw_result)

    # Get sample zip
    get_sample_zip_parser = subparsers.add_parser('get_sample_zip', help='Download a specific sample as a password-protected ZIP file')
    get_sample_zip_parser.add_argument('sha256', help='SHA256 hash of the sample')
    get_sample_zip_parser.add_argument('destination', help='Path where the ZIP file should be stored')
    get_sample_zip_parser.set_defaults(func=get_sample_zip_result)

    # Get YARA
    get_yara_parser = subparsers.add_parser('get_yara', help='Get YARA rules for a specific family')
    get_yara_parser.add_argument('family_id', help='ID of the family')
    get_yara_parser.set_defaults(func=get_yara_result)

    # Get YARA aggregated
    get_yara_aggregated_parser = subparsers.add_parser('get_yara_aggregated', help='Download all YARA rules as a single file')
    get_yara_aggregated_parser.add_argument('tlp', help='TLP level of the rules to download')
    get_yara_aggregated_parser.add_argument('--destination', help='Path where the YARA file should be stored', default='malpedia.yar')
    get_yara_aggregated_parser.set_defaults(func=get_yara_aggregated_result)

    # Get YARA after
    get_yara_after_parser = subparsers.add_parser('get_yara_after', help='Get YARA rules updated after a specific date')
    get_yara_after_parser.add_argument('date', help='Date in the format YYYY-MM-DD')
    get_yara_after_parser.set_defaults(func=get_yara_after_result)

    # Find family
    find_family_parser = subparsers.add_parser('find_family', help='Search for a family')
    find_family_parser.add_argument('needle', help='Search term')
    find_family_parser.set_defaults(func=find_family_result)

    # Find actor
    find_actor_parser = subparsers.add_parser('find_actor', help='Search for an actor')
    find_actor_parser.add_argument('needle', help='Search term')
    find_actor_parser.set_defaults(func=find_actor_result)

    # Get family
    get_family_parser = subparsers.add_parser('get_family', help='Get information about a specific family')
    get_family_parser.add_argument('family_id', help='ID of the family')
    get_family_parser.set_defaults(func=get_family_result)

    # Get families
    get_families_parser = subparsers.add_parser('get_families', help='Get information about all families')
    get_families_parser.set_defaults(func=get_families_result)

    # Get actor
    get_actor_parser = subparsers.add_parser('get_actor', help='Get information about a specific actor')
    get_actor_parser.add_argument('actor_id', help='ID of the actor')
    get_actor_parser.set_defaults(func=get_actor_result)

    # Get MISP
    get_misp_parser = subparsers.add_parser('get_misp', help='Get MISP data')
    get_misp_parser.set_defaults(func=get_misp_result)

    # Get version
    get_version_parser = subparsers.add_parser('get_version', help='Get version information')
    get_version_parser.set_defaults(func=get_version_result)

    # Scan binary
    scan_binary_parser = subparsers.add_parser('scan_binary', help='Scan a binary file with all YARA rules')
    scan_binary_parser.add_argument('filepath', help='Path to the binary file')
    scan_binary_parser.set_defaults(func=scan_binary_result)

    # Scan YARA
    scan_yara_parser = subparsers.add_parser('scan_yara', help='Scan a YARA rule against all samples')
    scan_yara_parser.add_argument('filepath', help='Path to the YARA rule file')
    scan_yara_parser.add_argument('--family_id', help='Optional family ID to limit the scan')
    scan_yara_parser.set_defaults(func=scan_yara_result)

    args = parser.parse_args()
    malpedia_client = malpediaclient.Client()
    _load_config_and_authenticate(malpedia_client)
    args.func(args, malpedia_client)

def list_families_result(args, malpedia_client):
    result = malpedia_client.list_families()
    _printj(result)

def list_actors_result(args, malpedia_client):
    result = malpedia_client.list_actors()
    _printj(result)

def list_samples_result(args, malpedia_client):
    result = malpedia_client.list_samples(args.family_id)
    _printj(result)

def list_yara_result(args, malpedia_client):
    result = malpedia_client.list_yara()
    _printj(result)

def list_apiscout_results(args, malpedia_client):
    if args.command == 'list_apiscout':
        result = malpedia_client.list_apiscout()
        _printj(result)
    elif args.command == 'list_apiscout_csv':
        malpedia_client.list_apiscout_csv(args.destination)

def get_sample_raw_result(args, malpedia_client):
    result = malpedia_client.get_sample_raw(args.sha256)
    _save_file(args.destination, result)

def get_sample_zip_result(args, malpedia_client):
    result = malpedia_client.get_sample_zip(args.sha256)
    _save_file(args.destination, result)

def get_yara_result(args, malpedia_client):
    result = malpedia_client.get_yara(args.family_id)
    _printj(result)

def get_yara_aggregated_result(args, malpedia_client):
    malpedia_client.get_yara_aggregated(args.tlp, args.destination)

def get_yara_after_result(args, malpedia_client):
    result = malpedia_client.get_yara_after(args.date)
    _printj(result)

def find_family_result(args, malpedia_client):
    result = malpedia_client.find_family(args.needle)
    _printj(result)

def find_actor_result(args, malpedia_client):
    result = malpedia_client.find_actor(args.needle)
    _printj(result)

def get_family_result(args, malpedia_client):
    result = malpedia_client.get_family(args.family_id)
    _printj(result)

def get_families_result(args, malpedia_client):
    result = malpedia_client.get_families()
    _printj(result)

def get_actor_result(args, malpedia_client):
    result = malpedia_client.get_actor(args.actor_id)
    _printj(result)

def get_misp_result(args, malpedia_client):
    result = malpedia_client.get_misp()
    _printj(result)

def get_version_result(args, malpedia_client):
    result = malpedia_client.get_version()
    _printj(result)

def scan_binary_result(args, malpedia_client):
    raise NotImplementedError("The command scan_binary_result is currently disabled server-side.")
    result = malpedia_client.scan_binary(args.filepath)
    _printj(result)

def scan_yara_result(args, malpedia_client):
    raise NotImplementedError("The command scan_binary_result is currently disabled server-side.")
    result = malpedia_client.scan_yara(args.filepath, args.family_id)
    _printj(result)

if __name__ == '__main__':
    main()

