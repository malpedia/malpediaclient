import requests
try:
    from urllib.parse import urljoin
except ImportError:
    # Python2 fallback
    from urlparse import urljoin
from requests.auth import HTTPBasicAuth
import os


class Client():
    """
    Python interface for functionalities provided by the REST Api of the Malpedia project.
    https://malpedia.caad.fkie.fraunhofer.de
    """

    def __init__(self, username=None, password=None, apitoken=None):
        """
        Initialize a new instance of the MalpediaApiClient.
        Optionally, login data for your useraccount on Malpedia can be provided.
        This can either be your username/password combination or an apitoken.

        Args:
            username: Your Malpedia username.
            password: Your Malpedia password.
        """
        self.__credentials = None
        self.__headers = {}
        if apitoken:
            self.authenticate_by_token(apitoken)
        if username and password:
            self.authenticate(username, password)

    def authenticate_by_token(self, apitoken):
        """
        Set apitoken for authentication

        Args:
            apitoken: A active Apitoken that was generated on Malpedia.
        """
        self.__headers.update({'Authorization': 'APIToken {}'.format(apitoken)})

    def authenticate(self, username, password):
        """
        Set credentials

        Args:
            username: Your Malpedia username.
            password: Your Malpedia password.
        """
        self.__credentials = HTTPBasicAuth(username, password)

    def list_families(self):
        """
        List all family IDs. This is a helper command to enable follow up commands family data.
        Access limitation: none
        """
        return self.__make_api_call('list/families')

    def list_actors(self):
        """
        List all actor IDs. This is a helper command to enable follow commands involving actor data.
        Access limitation: none
        """
        return self.__make_api_call('list/actors')

    def list_apiscout(self):
        """
        Provide a list of all non-zero ApiVector fingerprints that are currently on Malpedia.
        Access limitation: registration
        """
        return self.__make_api_call('list/apiscout')

    def list_apiscout_csv(self, destination):
        """
        Provide a list of all non-zero ApiVector fingerprints that are currently on Malpedia (in CSV format compatible with ApiScout).
        Access limitation: registration
        """
        res = self.__make_api_call('list/apiscout/csv', raw=True)
        with open(destination, "wb") as csvfile:
            csvfile.write(res)

    def get_yara_aggregated(self, tlp, destination="malpedia.yar"):
        """
        Provide all YARA rules with given TLP.
        Access limitation: registration
        """
        res = self.__make_api_call('get/yara/{}/raw'.format(tlp), raw=True)
        with open(destination, "wb") as csvfile:
            csvfile.write(res)

    def list_samples(self, family_id):
        """
        Provide a list of all samples known for a family, including their packed status and version, if available.
        Access limitation: registration
        """
        return self.__make_api_call('list/samples/{}'.format(family_id))

    def list_yara(self):
        """
        Provide a list of all YARA rules in malpedia for all families.
        Output may vary depending on access level (public = white, registration = green, amber).
        Access limitation: none (but result may vary for registered users)
        """
        return self.__make_api_call('list/yara')

    def get_family(self, family_id):
        """
        Provide meta data for a single family, as identified by <family_id>.
        Access limitation: none
        """
        return self.__make_api_call('get/family/{}'.format(family_id))

    def get_families(self):
        """
        Provide meta data for all families.
        Access limitation: none
        """
        return self.__make_api_call('get/families/')

    def get_sample_raw(self, sha256):
        """
        Provide the sample alongside potentially existing unpacked or dumped files.
        Access limitation: registration
        """
        return self.__make_api_call('get/sample/{}/raw'.format(sha256))

    def get_sample_zip(self, sha256):
        """
        Provide the sample alongside potentially existing unpacked or dumped files.
        Access limitation: registration
        """
        return self.__make_api_call('get/sample/{}/zip'.format(sha256))

    def get_yara(self, family_id):
        """
        Provide the YARA rules for a given <family_id>.
        Output may vary depending on access level (public = white, registration = green, amber).
        Access limitation: none (but result may vary for registered users)
        """
        return self.__make_api_call('get/yara/{}'.format(family_id))

    def get_actor(self, actor_id):
        """
        Provide the meta information for a given <actor_id>.
        Access limitation: none
        """
        return self.__make_api_call('get/actor/{}'.format(actor_id))

    def get_misp(self):
        """
        A current view of Malpedia in the MISP galaxy cluster format.
        Access limitation: none
        """
        return self.__make_api_call('get/misp')

    def get_version(self):
        """
        Obtain the current version of Malpedia (commit number and date).
        Access limitation: none
        """
        return self.__make_api_call('get/version')

    def get_yara_after(self, date):
        """
        Provide all YARA rules with a version newer than a specific date. Intended for users intending regular automated updates.
        Output may vary depending on access level (public = white, registration = green, amber).
        Access limitation: none (but result may vary for registered users)
        """
        return self.__make_api_call('get/yara/after/{}'.format(date))

    def find_family(self, needle):
        """
        Provide a list of all family names and associated synonyms where a part (<needle>) of the name is matched.
        Access limitation: none
        """
        return self.__make_api_call('find/family/{}'.format(needle))

    def find_actor(self, needle):
        """
        Provide a list of all actor names and associated synonyms where a part (<needle>) of the name is matched.
        Output is potentially subject to change and may include the responsible "name-creator" (e.g. "fireeye": "APT 28", "crowdstrike": "Fancy Bear", ...) in the future.
        Access limitation: none
        """
        return self.__make_api_call('find/actor/{}'.format(needle))

    def scan_binary(self, filepath):
        """
        Have a binary scanned against all YARA rules currently contained in Malpedia.
        The format of <yara_scan_report> is TBD.
        Access limitation: registration

        Args:
            filepath: Path to the file you wish to analyze. raw binary OR zip file (pwd:infected) containing one or more binaries.
        """
        with open(filepath, "rb") as input_file:
            return self.__make_api_call('scan/binary', files={'input_file': input_file}, method='POST')

    def scan_yara(self, filepath, family_id=None):
        """
        Have a YARA rule used to scan against all samples (packed, unpacked, dumped) currently contained in Malpedia.
        The format of <yara_scan_report> is TBD.
        Access limitation: registration

        Args:
            filepath: Path to the yara-rule.
        """
        url = 'scan/yara/{}'.format(family_id) if family_id else 'scan/yara'
        with open(filepath, "rb") as input_file:
            return self.__make_api_call(url, data=input_file.read(), method='POST')

    def __make_api_call(self, path, method='GET', files=None, data=None, raw=False):
        apicall_path = "https://malpedia.caad.fkie.fraunhofer.de/api/" + path.lstrip("/")
        response = requests.request(method, apicall_path, auth=self.__credentials, headers=self.__headers, files=files, data=data)
        if response.status_code == 200:
            if raw: return response.content
            return response.json()
        elif response.status_code == 403:
            raise Exception("Not authorized. You need to be authenticated for this API call.")
        elif response.status_code == 404:
            raise Exception("Not found. Either the resource you requested does not exist or you need to authenticate.")
        raise Exception("HTTP Status Code {:d}. Error while making request.".format(response.status_code))
