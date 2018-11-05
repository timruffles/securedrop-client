"""
Contains the crypto logic for the application.

Copyright (C) 2018  The Freedom of the Press Foundation.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
import subprocess
import pretty_bad_protocol as gnupg
import os
import shutil
import logging

logger = logging.getLogger(__name__)


class VaultGPG(object):
    """
    VaultGPG uses the gpg binary on the current system: if Qubes,
    it will use split-gpg.
    """
    def __init__(self, is_qubes, gpg_home_dir=None):
        if is_qubes:
            gpg_binary = 'qubes-gpg-client'
            self.gpg = gnupg.GPG(binary=gpg_binary)
        else:
            gpg_binary = 'gpg2'
            self.gpg = gnupg.GPG(binary=gpg_binary,
                                 homedir=gpg_home_dir)

    def decrypt_file_in_place(self, filepath):
        decrypted_path = filepath + '.decrypted'

        with open(filepath, 'rb') as f:
            ciphertext = f.read()

        result = self.gpg.decrypt(ciphertext)

        # result = self.gpg.decrypt_file(f,
        # output=decrypted_path)

        if result.ok:
            with open(decrypted_path, 'wb') as f:
                f.write(result.data)

            # Replace ciphertext with decrypted content
            shutil.move(decrypted_path, filepath)
            return True
        else:
            logging.info('Failed to decrypt file!')
            return False
