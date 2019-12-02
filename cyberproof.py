import sys
import requests


class Scanner:
    def __init__(self):
        try:
            self.session = requests.Session()
        except requests.exceptions.RequestException as e:
            print(e)
            sys.exit(1)

    def upload_and_scan(
            self,
            url,
            file,
            api_key,
    ):

        return self.session.post(
            url=url,
            files={'file': (file, open(file, 'rb'))},
            params={'apikey': api_key},
        ).json()

    def retrieve_report(
            self,
            resource_id,
            url,
            api_key,
    ):

        return self.session.post(
            url=url,
            params={
                'apikey': api_key,
                'resource': resource_id,
            },
        ).json()


if __name__ == '__main__':
    SCANNER_CONF = {
        'scanner_url': 'https://www.virustotal.com/vtapi/v2/file/scan',
        'report_url': 'https://www.virustotal.com/vtapi/v2/file/report',
        'api_key': '44287fd55fc398f9c70edb75a92b9b42d21d7c99b29625f414199975614df76f',
        'file': 'EICAR-AV-Test.txt',
    }

    file_scanner = Scanner()

    resource_id = file_scanner.upload_and_scan(
        SCANNER_CONF['scanner_url'],
        SCANNER_CONF['file'],
        SCANNER_CONF['api_key']
    )['resource']

    file_dict = file_scanner.retrieve_report(
        str(resource_id),
        SCANNER_CONF['report_url'],
        SCANNER_CONF['api_key'],
    )

    # there's no positives per engine as far as I could see so I couldn't match each engine to positives
    for key, value in file_dict.items():
        if key == 'positives' and value > 0:
            print(key, value)
