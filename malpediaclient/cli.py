import argparse
import malpediaclient
import pkg_resources
import json
import os
import base64
import sys
from operator import itemgetter

CONFIG_LOCATIONS = [
    # Current directory
    os.path.join(os.curdir, "malpedia.json"),
    os.path.join(os.curdir, ".malpedia.json"),
    # Linux user takes precedence over linux system
    "$HOME/.malpedia.json",
    "/etc/malpedia.json",
    # Windows
    R"${APPDATA}\malpedia\malpedia.json",
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
                    print("[!] Found config file \"{}\" but it does neither contain an apitoken nor a username and password.".format(loc))
                    return False
        except json.JSONDecodeError as err:
            print("[!] Found config file \"{}\" but it does not contain valid JSON: {}".format(loc, err.msg))
            return False
        except IOError:
            # look for the next possible location
            pass

    if not has_config:
        try:
            # try to import a python config file
            # This is for backwards compatibility
            import config
            if config.MALPEDIA_APITOKEN:
                apitoken = config.MALPEDIA_APITOKEN
            elif config.MALPEDIA_USERNAME and config.MALPEDIA_PASSWORD:
                username = config.MALPEDIA_USERNAME
                password = config.MALPEDIA_PASSWORD
        except:
            return False

    # at this point we are guaranteed to either have an apitoken or a username and password
    if apitoken:
        print("[*] Using apitoken from config")
        malpedia_client.authenticate_by_token(apitoken)
    else:
        print("[*] Using credentials from config (username: \"{}\")".format(username))
        malpedia_client.authenticate(username, password)
    return True

def _printj(result):
    print(json.dumps(result, sort_keys=True, indent=2))


def _save_file(path, content, is_base64=False):
    dir_path = os.path.dirname(path)
    if not os.path.exists(dir_path): os.makedirs(dir_path)
    with open(path, "wb") as outfile:
        if is_base64: outfile.write(base64.decodestring(bytes(content, "utf-8")))
        else: outfile.write(content.encode('utf-8'))


# make python2 error output a bit nicer
# courtesy of https://stackoverflow.com/a/14912282
class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('[x] error: %s\n\n' % message)
        self.print_help()
        sys.exit(2)


def main():
    malpedia_client = malpediaclient.Client()

    parser = MyParser(description="Malpedia REST API Client (https://malpedia.caad.fkie.fraunhofer.de)")
    try:
        client_version = pkg_resources.get_distribution("malpediaclient").version
    except:
        client_version = malpediaclient.__version__
    parser.add_argument("--version", action="version", version="malpediaclient {}".format(client_version))
    parser.set_defaults(func=lambda args: parser.print_help())
    has_config = _load_config_and_authenticate(malpedia_client)
    if not has_config:
        print("[!] No configuration file found, requiring credentials/token from cmdline parameters if needed.")
        # if there is no config file, the user needs to specify username+password
        parser.add_argument('--credentials', type=str, help="Credentials for malpedia in the form username:password", required=False)
        parser.add_argument('--apitoken', type=str, help="Apitoken for malpedia", required=False)

    subparsers = parser.add_subparsers(title="apicalls")

    def list_families_result(args):
        result = malpedia_client.list_families()
        for family_id in result:
            print(family_id)
    list_families = subparsers.add_parser("list-families", help="List all family IDs. This is a helper command to enable follow up commands family data.")
    list_families.set_defaults(api_func=list_families_result)

    def list_actors_result(args):
        result = malpedia_client.list_actors()
        for actor_id in result:
            print(actor_id)
    list_actors = subparsers.add_parser("list-actors", help="List all actor IDs. This is a helper command to enable follow commands involving actor data.")
    list_actors.set_defaults(api_func=list_actors_result)

    def list_samples_result(args):
        result = malpedia_client.list_samples(args.family_id)
        for sample in result:
            print("{sample[sha256]} | {sample[status]} | {sample[version]}".format(sample=sample))
    list_samples = subparsers.add_parser("list-samples", help="Provide a list of all samples known for a family, including their packed status and version, if available.")
    list_samples.add_argument("family_id", type=str, help="ID of the Family you would like to list the samples of.")
    list_samples.set_defaults(api_func=list_samples_result)

    def list_yara_result(args):
        result = malpedia_client.list_yara()
        for family, rules in sorted(result.items(), key=itemgetter(0)):
            print("---\n{}\n---".format(family))
            for rule in rules:
                print("[{}] {}".format(rule["tlp"].replace("tlp_", "tlp:").upper(), rule["path"]))
    list_yara = subparsers.add_parser("list-yara", help="Provide a list of all YARA rules in malpedia for all families. Output may vary depending on access level (public = white, registration = green, amber).")
    list_yara.set_defaults(api_func=list_yara_result)

    def list_apiscout_results(args):
        if args.destination:
            malpedia_client.list_apiscout_csv(args.destination)
            print("The results were saved in {}".format(args.destination))
        else:
            result = malpedia_client.list_apiscout()
            for path, apivector in sorted(result.items(), key=itemgetter(0)):
                print("{}\n{}\n---".format(path, apivector))
    list_apiscout = subparsers.add_parser("list-apiscout", help="Provide a list of all non-zero ApiVector fingerprints that are currently on Malpedia.")
    list_apiscout.add_argument("--destination", "-d", type=str, help="Save the results to a .csv-file at the given path.")
    list_apiscout.set_defaults(api_func=list_apiscout_results)

    get_family = subparsers.add_parser("get-family", help="Provide meta data for a single family.")
    get_family.add_argument("family_id", type=str, help="ID of the Family you would like to obtain.")
    get_family.set_defaults(api_func=lambda args: _printj(malpedia_client.get_family(args.family_id)))

    get_misp = subparsers.add_parser("get-misp", help="A current view of Malpedia in the MISP galaxy cluster format.")
    get_misp.set_defaults(api_func=lambda args: _printj(malpedia_client.get_misp()))

    get_version = subparsers.add_parser("get-version", help="Obtain the current version of Malpedia (commit number and date).")
    get_version.set_defaults(api_func=lambda args: _printj(malpedia_client.get_version()))

    def get_sample_raw_result(args):
        result = malpedia_client.get_sample_raw(sha256=args.sha256)
        print("The following files were downloaded:")
        for raw_filename, content in result.items():
            filename = os.path.join(args.destination, args.sha256)
            if raw_filename != "packed": filename += "_{}".format(raw_filename)
            _save_file(filename, content, is_base64=True)
            print(filename)
    get_sample_raw = subparsers.add_parser("get-sample-raw", help="Provide the sample alongside potentially existing unpacked or dumped files.")
    get_sample_raw.add_argument("sha256", type=str, help="SHA256 checksum of the sample you would like to download.")
    get_sample_raw.add_argument("--destination", "-d", type=str, help="Destination directory for sample downloads. Default: %(default)s", default="samples")
    get_sample_raw.set_defaults(api_func=get_sample_raw_result)

    def get_sample_zip_result(args):
        result = malpedia_client.get_sample_zip(sha256=args.sha256)
        filename = os.path.join(args.destination, args.sha256 + ".zip")
        _save_file(filename, result["zipped"], is_base64=True)
        print("The zipfile was downloaded to:\n{}".format(filename))
    get_sample_zip = subparsers.add_parser("get-sample-zip", help="Provide the sample alongside potentially existing unpacked or dumped files.")
    get_sample_zip.add_argument("sha256", type=str, help="SHA256 checksum of the sample you would like to download.")
    get_sample_zip.add_argument("--destination", "-d", type=str, help="Destination directory for sample downloads. Default: %(default)s", default="samples")
    get_sample_zip.set_defaults(api_func=get_sample_zip_result)

    def get_yara_result(args):
        result = malpedia_client.get_yara(args.family_id)
        print("The following rules were downloaded:")
        for tlp, rules in result.items():
            for raw_filename, content in rules.items():
                filename = os.path.join(args.destination, raw_filename)
                _save_file(filename, content, is_base64=False)
                print(filename)
    get_yara = subparsers.add_parser("get-yara", help=" Provide the YARA rules for a given <family_id>. Output may vary depending on access level (public = white, registration = green, amber).")
    get_yara.add_argument("family_id", type=str, help="ID of the Family you would like to list the yara-rules of.")
    get_yara.add_argument("--destination", "-d", type=str, help="Destination directory for yara downloads. Default: %(default)s", default="yara")
    get_yara.set_defaults(api_func=get_yara_result)

    def get_yara_aggregated_result(args):
        malpedia_client.get_yara_aggregated(args.tlp, args.destination)
        print("The file was saved to {}.".format(args.destination))
    get_yara_aggregated = subparsers.add_parser("get-yara-aggregated", help="Provide all YARA rules with given TLP. Output may vary depending on access level (public = white, registration = green, amber).")
    get_yara_aggregated.add_argument("tlp", type=str, help="The highest tlp you want to have included in the .yar-file.", default="tlp_amber")
    get_yara_aggregated.add_argument("--destination", "-d", type=str, help="Destination path for aggregated yara file. Default: %(default)s", default="malpedia.yar")
    get_yara_aggregated.set_defaults(api_func=get_yara_aggregated_result)

    get_actor = subparsers.add_parser("get-actor", help="Provide meta data for a single actor.")
    get_actor.add_argument("actor_id", type=str, help="ID of the Actor you would like to obtain.")
    get_actor.set_defaults(api_func=lambda args: _printj(malpedia_client.get_actor(args.actor_id)))

    def get_yara_after_result(args):
        result = malpedia_client.get_yara_after(args.date)
        print("The following rules were downloaded:")
        for tlp, rules in result.items():
            for raw_filename, content in rules.items():
                filename = os.path.join(args.destination, raw_filename)
                _save_file(filename, content, is_base64=False)
                print(filename)
    get_yara_after = subparsers.add_parser("get-yara-after", help="Provide the YARA rules for a given <family_id>. This is similar to GET get/family/<family_id>/yara. Output may vary depending on access level (public = white, registration = green, amber).")
    get_yara_after.add_argument("date", type=str, help="Sate of the oldest Yara-Rule you want to download (format: YYYY-MM-DD).")
    get_yara_after.add_argument("--destination", "-d", type=str, help="Destination directory for yara downloads. Default: %(default)s", default="yara")
    get_yara_after.set_defaults(api_func=get_yara_after_result)

    def find_family_result(args):
        result = malpedia_client.find_family(args.needle)
        for family in result:
            if family["alt_names"]:
                print("{} [{}]".format(family["name"], ", ".join(map(lambda x: "'{}'".format(x), family["alt_names"]))))
            else: print(family["name"])
    find_family = subparsers.add_parser("find-family", help="Provide a list of all family names and associated synonyms where a part (<needle>) of the name is matched.")
    find_family.add_argument("needle", type=str, help="Your search-string.")
    find_family.set_defaults(api_func=find_family_result)

    def find_actor_result(args):
        result = malpedia_client.find_actor(args.needle)
        for actor in result:
            print("{} [{}]".format(actor["name"], ", ".join(map(lambda x: "'{}'".format(x), [actor["common_name"]] + actor["synonyms"]))))
    find_actor = subparsers.add_parser("find-actor", help="Provide a list of all actor names and associated synonyms where a part (<needle>) of the name is matched. Output is potentially subject to change and may include the responsible 'name-creator' (e.g. 'fireeye': 'APT 28', 'crowdstrike': 'Fancy Bear', ...) in the future.")
    find_actor.add_argument("needle", type=str, help="Your search-string.")
    find_actor.set_defaults(api_func=find_actor_result)

    scan_binary = subparsers.add_parser("scan-binary", help="Have a binary scanned against all YARA rules currently contained in Malpedia.")
    scan_binary.add_argument("path", type=str, help="Path to the file you wish to analyze. raw binary OR zip file (pwd:infected) containing one or more binaries.")
    scan_binary.set_defaults(api_func=lambda args: _printj(malpedia_client.scan_binary(args.path)))

    scan_yara = subparsers.add_parser("scan-yara", help="Have a YARA rule used to scan against all samples (packed, unpacked, dumped) currently contained in Malpedia.")
    scan_yara.add_argument("path", type=str, help="path to the Yara-Rule you would like to scan with.")
    scan_yara.set_defaults(api_func=lambda args: _printj(malpedia_client.scan_yara(args.path)))

    args = parser.parse_args()
    if not has_config:
        if args.apitoken:
            malpedia_client.authenticate_by_token(args.apitoken)
        if args.credentials:
            username, password = args.credentials.split(":")
            malpedia_client.authenticate(username, password)
    if "api_func" in args:
        print("[+] Results: \n")
        args.api_func(args)
    else:
        args.func(args)

