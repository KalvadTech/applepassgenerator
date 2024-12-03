# Standard Library
import decimal
import hashlib
import json
import zipfile
from io import BytesIO

# Third Party Stuff
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from applepassgenerator.enums import (
    BarcodeFormat,
)
from applepassgenerator.fields import Barcode


class ApplePass(object):
    def __init__(
        self,
        pass_information,
        json="",
        pass_type_identifier="",
        organization_name="",
        team_identifier="",
    ):
        self._files = {}  # Holds the files to include in the .pkpass
        self._hashes = {}  # Holds the SHAs of the files array

        # Standard Keys

        # Required. Team identifier of the organization that originated and
        # signed the pass, as issued by Apple.
        self.team_identifier = team_identifier
        # Required. Pass type identifier, as issued by Apple. The value must
        # correspond with your signing certificate. Used for grouping.
        self.pass_type_identifier = pass_type_identifier
        # Required. Display name of the organization that originated and
        # signed the pass.
        self.organization_name = organization_name
        # Required. Serial number that uniquely identifies the pass.
        self.serial_number = ""
        # Required. Brief description of the pass, used by the iOS
        # accessibility technologies.
        self.description = ""
        # Required. Version of the file format. The value must be 1.
        self.format_version = 1

        # Visual Appearance Keys
        self.background_color = None  # Optional. Background color of the pass
        self.foreground_color = None  # Optional. Foreground color of the pass,
        self.label_color = None  # Optional. Color of the label text
        self.logo_text = None  # Optional. Text displayed next to the logo
        self.barcode = None  # Optional. Information specific to barcodes. This is deprecated and can only be set to original barcode formats.
        self.barcodes = None  # Optional.  All supported barcodes
        # Optional. If true, the strip image is displayed
        self.suppress_strip_shine = False

        # Web Service Keys

        # Optional. If present, authentication_token must be supplied
        self.web_service_url = None
        # The authentication token to use with the web service
        self.authentication_token = None

        # Relevance Keys

        # Optional. Locations where the pass is relevant.
        # For example, the location of your store.
        self.locations = None
        # Optional. IBeacons data
        self.ibeacons = None
        # Optional. Date and time when the pass becomes relevant
        self.relevant_date = None

        # Optional. A list of iTunes Store item identifiers for
        # the associated apps.
        self.associated_store_identifiers = None
        self.app_launch_url = None
        # Optional. Additional hidden data in json for the passbook
        self.user_info = None

        self.expiration_date = None
        self.voided = None

        self.pass_information = pass_information

    # Adds file to the file array
    def add_file(self, name, fd):
        self._files[name] = fd.read()

    # Creates the actual .pkpass file
    def create(self, certificate, key, wwdr_certificate, password, zip_file=None):
        pass_json = self._create_pass_json()
        manifest = self._create_manifest(pass_json)
        signature = self._create_signature_crypto(
            manifest, certificate, key, wwdr_certificate, password
        )

        if not zip_file:
            zip_file = BytesIO()
        self._create_zip(pass_json, manifest, signature, zip_file=zip_file)
        return zip_file

    def _create_pass_json(self):
        return json.dumps(self, default=pass_handler)

    def _create_manifest(self, pass_json):
        """
        Creates the hashes for all the files included in the pass file.
        """
        self._hashes["pass.json"] = hashlib.sha1(pass_json.encode("utf-8")).hexdigest()
        for filename, filedata in self._files.items():
            self._hashes[filename] = hashlib.sha1(filedata).hexdigest()
        return json.dumps(self._hashes)

    def _read_file_bytes(self, path):
        """
        Utility function to read files as byte data
        :param path: file path
        :returns bytes
        """
        file = open(path)
        return file.read().encode("UTF-8")

    def _create_signature_crypto(
        self, manifest, certificate, key, wwdr_certificate, password
    ):
        """
        Creates a signature (DER encoded) of the manifest.
        Rewritten to use cryptography library instead of M2Crypto
        The manifest is the file
        containing a list of files included in the pass file (and their hashes).
        """
        cert = x509.load_pem_x509_certificate(self._read_file_bytes(certificate))
        if password is not None:
            password = password.encode("UTF-8")
        priv_key = serialization.load_pem_private_key(
            self._read_file_bytes(key), password=password
        )
        wwdr_cert = x509.load_pem_x509_certificate(
            self._read_file_bytes(wwdr_certificate)
        )

        options = [pkcs7.PKCS7Options.DetachedSignature]
        return (
            pkcs7.PKCS7SignatureBuilder()
            .set_data(manifest.encode("UTF-8"))
            .add_signer(cert, priv_key, hashes.SHA1())
            .add_certificate(wwdr_cert)
            .sign(serialization.Encoding.DER, options)
        )

    # Creates .pkpass (zip archive)
    def _create_zip(self, pass_json, manifest, signature, zip_file=None):
        zf = zipfile.ZipFile(zip_file or "pass.pkpass", "w")
        zf.writestr("signature", signature)
        zf.writestr("manifest.json", manifest)
        zf.writestr("pass.json", pass_json)
        for filename, filedata in self._files.items():
            zf.writestr(filename, filedata)
        zf.close()

    def json_dict(self):
        d = {
            "description": self.description,
            "formatVersion": self.format_version,
            "organizationName": self.organization_name,
            "passTypeIdentifier": self.pass_type_identifier,
            "serialNumber": self.serial_number,
            "teamIdentifier": self.team_identifier,
            "suppressStripShine": self.suppress_strip_shine,
            self.pass_information.jsonname: self.pass_information.json_dict(),
        }
        # barcodes have 2 fields, 'barcode' is legacy so limit it to the legacy formats, 'barcodes' supports all
        if self.barcode:
            original_formats = [
                BarcodeFormat.PDF417,
                BarcodeFormat.QR,
                BarcodeFormat.AZTEC,
            ]
            legacy_barcode = self.barcode
            new_barcodes = [self.barcode.json_dict()]
            if self.barcode.format not in original_formats:
                legacy_barcode = Barcode(
                    self.barcode.message, BarcodeFormat.PDF417, self.barcode.altText
                )
            d.update({"barcodes": new_barcodes})
            d.update({"barcode": legacy_barcode})

        if self.relevant_date:
            d.update({"relevantDate": self.relevant_date})
        if self.background_color:
            d.update({"backgroundColor": self.background_color})
        if self.foreground_color:
            d.update({"foregroundColor": self.foreground_color})
        if self.label_color:
            d.update({"labelColor": self.label_color})
        if self.logo_text:
            d.update({"logoText": self.logo_text})
        if self.locations:
            d.update({"locations": self.locations})
        if self.ibeacons:
            d.update({"beacons": self.ibeacons})
        if self.user_info:
            d.update({"userInfo": self.user_info})
        if self.associated_store_identifiers:
            d.update({"associatedStoreIdentifiers": self.associated_store_identifiers})
        if self.app_launch_url:
            d.update({"appLaunchURL": self.app_launch_url})
        if self.expiration_date:
            d.update({"expirationDate": self.expiration_date})
        if self.voided:
            d.update({"voided": True})
        if self.web_service_url:
            d.update(
                {
                    "webServiceURL": self.web_service_url,
                    "authenticationToken": self.authentication_token,
                }
            )
        return d


def pass_handler(obj):
    if hasattr(obj, "json_dict"):
        return obj.json_dict()
    else:
        # For Decimal latitude and longitude etc
        if isinstance(obj, decimal.Decimal):
            return str(obj)
        else:
            return obj
