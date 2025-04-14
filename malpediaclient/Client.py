import requests
from urllib.parse import urljoin
from requests.auth import HTTPBasicAuth
import os


class Client:
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
            apitoken: Your Malpedia API token.
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
        self.__headers.update({'Authorization': f'APIToken {apitoken}'})

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
        List all available families.
        """
        return self.__make_api_call('api/list/families')

    def list_actors(self):
        """
        List all available actors.
        """
        return self.__make_api_call('api/list/actors')

    def list_apiscout(self):
        """
        List all available ApiScout data.
        """
        return self.__make_api_call('api/list/apiscout')

    def list_apiscout_csv(self, destination):
        """
        Download ApiScout data as CSV.

        Args:
            destination: Path where the CSV file should be stored.
        """
        result = self.__make_api_call('api/list/apiscout/csv', raw=True)
        with open(destination, 'wb') as f:
            f.write(result)

    def get_yara_aggregated(self, tlp, destination="malpedia.yar"):
        """
        Download all YARA rules as a single file.

        Args:
            tlp: TLP level of the rules to download.
            destination: Path where the YARA file should be stored.
        """
        result = self.__make_api_call(f'api/get/yara/aggregated/{tlp}', raw=True)
        with open(destination, 'wb') as f:
            f.write(result)

    def list_samples(self, family_id):
        """
        List all samples for a given family.

        Args:
            family_id: ID of the family.
        """
        return self.__make_api_call(f'api/list/samples/{family_id}')

    def list_yara(self):
        """
        List all available YARA rules.

        Returns:
            A list of all available YARA rules.
        """
        return self.__make_api_call('api/list/yara')

    def get_family(self, family_id):
        """
        Get information about a specific family.

        Args:
            family_id: ID of the family.
        """
        return self.__make_api_call(f'api/get/family/{family_id}')

    def get_families(self):
        """
        Get information about all families.
        """
        return self.__make_api_call('api/get/families')

    def get_sample_raw(self, sha256):
        """
        Download a specific sample.

        Args:
            sha256: SHA256 hash of the sample.
        """
        return self.__make_api_call(f'api/get/sample/{sha256}/raw', raw=True)

    def get_sample_zip(self, sha256):
        """
        Download a specific sample as a password-protected ZIP file.

        Args:
            sha256: SHA256 hash of the sample.
        """
        return self.__make_api_call(f'api/get/sample/{sha256}/zip', raw=True)

    def get_yara(self, family_id):
        """
        Get YARA rules for a specific family.

        Args:
            family_id: ID of the family.

        Returns:
            YARA rules for the specified family.
        """
        return self.__make_api_call(f'api/get/yara/{family_id}')

    def get_actor(self, actor_id):
        """
        Get information about a specific actor.

        Args:
            actor_id: ID of the actor.
        """
        return self.__make_api_call(f'api/get/actor/{actor_id}')

    def get_misp(self):
        """
        Get MISP data.
        """
        return self.__make_api_call('api/get/misp')

    def get_version(self):
        """
        Get version information.
        """
        return self.__make_api_call('api/get/version')

    def get_yara_after(self, date):
        """
        Get YARA rules updated after a specific date.

        Args:
            date: Date in the format YYYY-MM-DD.

        Returns:
            YARA rules updated after the specified date.
        """
        return self.__make_api_call(f'api/get/yara/after/{date}')

    def find_family(self, needle):
        """
        Search for a family.

        Args:
            needle: Search term.
        """
        return self.__make_api_call(f'api/find/family/{needle}')

    def find_actor(self, needle):
        """
        Search for an actor.

        Args:
            needle: Search term.
        """
        return self.__make_api_call(f'api/find/actor/{needle}')

    def scan_binary(self, filepath):
        """
        Scan a binary file with all YARA rules.

        Args:
            filepath: Path to the binary file.
        """
        with open(filepath, 'rb') as f:
            files = {'file': f}
            return self.__make_api_call('api/scan/binary', method='POST', files=files)

    def scan_yara(self, filepath, family_id=None):
        """
        Scan a YARA rule against all samples.

        Args:
            filepath: Path to the YARA rule file.
            family_id: Optional family ID to limit the scan.
        """
        with open(filepath, 'rb') as f:
            files = {'file': f}
            if family_id:
                return self.__make_api_call(f'api/scan/yara/{family_id}', method='POST', files=files)
            else:
                return self.__make_api_call('api/scan/yara', method='POST', files=files)

    def __make_api_call(self, path, method='GET', files=None, data=None, raw=False):
        """
        Make an API call to the Malpedia REST API.

        Args:
            path: API endpoint path.
            method: HTTP method to use.
            files: Files to upload.
            data: Data to send.
            raw: Whether to return the raw response.

        Returns:
            API response.
        """
        url = urljoin('https://malpedia.caad.fkie.fraunhofer.de/', path)
        if method == 'GET':
            response = requests.get(url, auth=self.__credentials, headers=self.__headers)
        elif method == 'POST':
            response = requests.post(url, auth=self.__credentials, headers=self.__headers, files=files, data=data)
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

        if response.status_code != 200:
            raise Exception(f"API call failed with status code {response.status_code}: {response.text}")

        if raw:
            return response.content
        return response.json()
