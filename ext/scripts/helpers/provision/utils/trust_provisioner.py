import json
import random
from configparser import ConfigParser, ExtendedInterpolation


class TrustProvisioner:
    """
    Class is a wrapper around TrustProvisioner process
    """
    def __init__(self, tp_process):
        """
        :param tp_process: instance of CmdSubProcess for TrustProvisioner
        """
        self.tp = tp_process

    def enter_date(self, year, month, day):
        self.tp.wait_for_output('Enter year (yyyy):')
        self.tp.send_to_stdin('%s' % year)
        self.tp.wait_for_output('Enter month (1-12):')
        self.tp.send_to_stdin('%s' % month)
        self.tp.wait_for_output('Enter day (1-31):')
        self.tp.send_to_stdin('%s' % day)
        self.tp.wait_for_output('Year: %s, Month: %s, Day: %s. Confirm? [y/n]' % (year, month, day))
        self.tp.send_to_stdin('y')

    def generate_upper_level_keys(self):

        # Start generation
        self.tp.wait_for_output('Please enter option number:')
        self.tp.send_to_stdin('1')

        # Generate 2 recovery keys
        for n in range(1, 3):
            self.tp.wait_for_output('Add start and expiration date for key? [y/n]:')
            self.tp.send_to_stdin('y')
            self.enter_date('2020', '6', '2')
            self.tp.wait_for_output('Enter expiration date? [y/n]:')
            self.tp.send_to_stdin('n')
            self.tp.wait_for_output('Enter comment for Recovery Key:')
            self.tp.send_to_stdin('recovery%s' % n)
            self.tp.wait_for_output('Virgil Card for key successfully registered')

        # Generate 2 auth keys
        for n in range(1, 3):
            self.tp.wait_for_output('Please enter option number:')
            self.tp.send_to_stdin(self._random_recovery())
            self.tp.wait_for_output('Add start and expiration date for key? [y/n]:')
            self.tp.send_to_stdin('n')
            self.tp.wait_for_output('Enter comment for Auth Key:')
            self.tp.send_to_stdin('auth%s' % n)
            self.tp.wait_for_output('Virgil Card for key successfully registered')

        # Generate 2 trust list keys
        for n in range(1, 3):
            self.tp.wait_for_output('Please enter option number:')
            self.tp.send_to_stdin(self._random_recovery())
            self.tp.wait_for_output('Add start and expiration date for key? [y/n]:')
            self.tp.send_to_stdin('n')
            self.tp.wait_for_output('Enter comment for TrustList Key:')
            self.tp.send_to_stdin('tl%s' % n)
            self.tp.wait_for_output('Virgil Card for key successfully registered')

        # Generate 2 firmware keys
        for n in range(1, 3):
            self.tp.wait_for_output('Please enter option number:')
            self.tp.send_to_stdin(self._random_recovery())
            self.tp.wait_for_output('Add start and expiration date for key? [y/n]:')
            self.tp.send_to_stdin('n')
            self.tp.wait_for_output('Enter comment for Firmware Key:')
            self.tp.send_to_stdin('firmware%s' % n)
            self.tp.wait_for_output('Virgil Card for key successfully registered')

        # Generate factory key
        self.tp.wait_for_output('Enter the signature limit number from 1 to 4294967295')
        signature_limit = str(random.choice(range(1, 4294967295)))
        self.tp.send_to_stdin(str(signature_limit))
        self.enter_date('2021', '7', '3')

        self.tp.wait_for_output('Enter expiration date? [y/n]:')
        self.tp.send_to_stdin('y')
        self.enter_date('2022', '7', '3')

        self.tp.wait_for_output('Enter comment for Factory Key:')
        self.tp.send_to_stdin('factory')
        self.tp.wait_for_output('Virgil Card for key successfully registered')

    def _generate_trust_list(self, *, auth_key_id=None, tl_service_key_id=None, version='0.0.0.0'):
        self.tp.wait_for_output('Please enter option number:')

        # Start trust list generation
        self.tp.send_to_stdin('8')

        # Wait for cloud key being retrieved
        self.tp.wait_for_output('Cloud key received and stored')

        # Select version
        self.tp.wait_for_output('Enter the TrustList version')
        self.tp.send_to_stdin(version)

        self.tp.wait_for_output('Are you sure you want change current TrustList version to')
        self.tp.send_to_stdin('Y')

        # Choose Auth key
        self.tp.wait_for_output('Please choose Auth Key for TrustList signing:')
        self.tp.wait_for_output('Please enter option number:')
        if auth_key_id:
            choice = self._get_choice_number_by_output(auth_key_id)
        else:
            choice = '1'
        self.tp.send_to_stdin(choice)

        # Choose Trust List key
        self.tp.wait_for_output('Please choose TrustList Key for TrustList signing:')
        self.tp.wait_for_output('Please enter option number:')
        if tl_service_key_id:
            choice = self._get_choice_number_by_output(tl_service_key_id)
        else:
            choice = '1'
        self.tp.send_to_stdin(choice)

        self.tp.wait_for_output('TrustList generated and stored')

    def generate_auth_keys(self):
        self.tp.send_to_stdin('3')
        for n in range(1, 3):
            self.tp.wait_for_output('Please enter option number:')
            self.tp.send_to_stdin(self._random_recovery())
            self.tp.wait_for_output('Add start and expiration date for key? [y/n]:')
            self.tp.send_to_stdin('n')
            self.tp.wait_for_output('Enter comment for Auth Key:')
            self.tp.send_to_stdin('auth%s' % n)
        self.tp.wait_for_output('Virgil Card for key successfully registered')
        self.tp.wait_for_output('Generation finished')

    def generate_firmware_keys(self):
        self.tp.send_to_stdin('7')
        for n in range(1, 3):
            self.tp.wait_for_output('Please enter option number:')
            self.tp.send_to_stdin(self._random_recovery())
            self.tp.wait_for_output('Add start and expiration date for key? [y/n]:')
            self.tp.send_to_stdin('n')
            self.tp.wait_for_output('Enter comment for Firmware Key:')
            self.tp.send_to_stdin('firmware%s' % n)
        self.tp.wait_for_output('Virgil Card for key successfully registered')
        self.tp.wait_for_output('Generation finished')

    def generate_release_trust_list(self, auth_key_id=None, tl_service_key_id=None, version='0.0.0.0'):
        self._generate_trust_list(
            auth_key_id=auth_key_id,
            tl_service_key_id=tl_service_key_id,
            version=version
        )

    def export_provision_package(self):
        self.tp.wait_for_output('Please enter option number:')
        self.tp.send_to_stdin('11')
        self.tp.wait_for_output('Provision package for Factory saved as')

    def export_public_keys(self):
        self.tp.wait_for_output('Please enter option number:')
        self.tp.send_to_stdin('12')
        self.tp.wait_for_output('Export finished')

    def export_private_keys(self):
        self.tp.wait_for_output('Please enter option number:')
        self.tp.send_to_stdin('13')
        self.tp.wait_for_output('Export finished')

    def exit(self):
        self.tp.wait_for_output('Please enter option number:')
        self.tp.send_to_stdin('14')

    def _get_choice_number_by_output(self, pattern):
        """
        Extracts choice number from line by pattern. Example line:
        2. db: AuthPrivateKeys, type: auth, comment: auth_2, key_id: 11913
        _get_choice_number_by_output('11913') -> 2
        """
        choice_line = [line for line in self.tp.output[self.tp.stdout_offset:] if pattern in line][0]
        return choice_line.strip()[0]

    def _random_recovery(self):
        return random.choice(['1', '2'])


def create_config(config_path,
                  storage_path,
                  log_path,
                  provision_pack_path,
                  iot_api_url):
    """
    Create config for TrustProvisioner
    """
    parser = ConfigParser(interpolation=ExtendedInterpolation())
    parser['MAIN'] = {
        'storage_path': storage_path,
        'log_path': log_path,
        'provision_pack_path': provision_pack_path
    }
    parser['VIRGIL'] = {
        'iot_api_url': iot_api_url,

    }
    with open(config_path, 'w') as configfile:
        parser.write(configfile)


def create_factory_info_json(json_path):
    data = {
        'name': 'Sample Factory Name',
        'address': 'sample address',
        'contacts': 'sample_factory@some_mail.com'
    }

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
