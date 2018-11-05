import os
import tempfile

from securedrop_client.crypto import VaultGPG


def test_gpg_file_decrypts_with_correct_key(safe_tmpdir):
    # Import private key
    with open('tests/files/test_journo.sec', 'rb') as f:
        secret_key = f.read()

    with tempfile.TemporaryDirectory() as tmpdir:
        crypto_obj = VaultGPG(False, gpg_home_dir=tmpdir)

        key_import_result = crypto_obj.gpg.import_keys(secret_key)

        filepath = os.path.abspath(
            'tests/files/1-impractical_thing-doc.gz.gpg')
        result = crypto_obj.decrypt_file_in_place(
            filepath)

    assert result


def test_gpg_consistency(safe_tmpdir):
    # Import private key
    with open('tests/files/test_journo.sec', 'rb') as f:
        secret_key = f.read()

    with tempfile.TemporaryDirectory() as tmpdir:
        crypto_obj = VaultGPG(False, gpg_home_dir=tmpdir)

        key_import_result = crypto_obj.gpg.import_keys(secret_key)

        test_message = 'test'
        ciphertext = crypto_obj.gpg.encrypt(
            test_message,
            key_import_result.fingerprints[0])
        plaintext = crypto_obj.gpg.decrypt(ciphertext.data)

    assert plaintext.data.decode('utf-8') == test_message


def test_gpg_file_does_not_decrypt_with_no_correct_key(safe_tmpdir):
    # Create gpg object without private key
    crypto_obj = VaultGPG(False, gpg_home_dir=str(safe_tmpdir))

    filepath = os.path.abspath(
        'tests/files/1-impractical_thing-doc.gz.gpg')
    result = crypto_obj.decrypt_file_in_place(
        filepath)

    assert not result
