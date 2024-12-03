# ruff: noqa: S324, S303
# Standard Library
import decimal
import hashlib
import json
import zipfile
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Optional, Union

# Third Party Stuff
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from applepassgenerator.enums import BarcodeFormat
from applepassgenerator.fields import Barcode


@dataclass
class ApplePass:
    """
    Represents an Apple Wallet pass that can be created and signed.

    Required Parameters:
        pass_information: Information specific to the pass type
        pass_type_identifier: Identifier issued by Apple
        organization_name: Name of the organization
        team_identifier: Team identifier issued by Apple
    """

    pass_information: Any
    pass_type_identifier: str
    organization_name: str
    team_identifier: str

    # Required fields with defaults
    serial_number: str = ""
    description: str = ""
    format_version: int = 1

    # Optional fields
    background_color: Optional[str] = None
    foreground_color: Optional[str] = None
    label_color: Optional[str] = None
    logo_text: Optional[str] = None
    barcode: Optional[Barcode] = None
    barcodes: Optional[list] = None
    suppress_strip_shine: bool = False

    # Web Service fields
    web_service_url: Optional[str] = None
    authentication_token: Optional[str] = None

    # Relevance fields
    locations: Optional[list] = None
    ibeacons: Optional[list] = None
    relevant_date: Optional[str] = None

    # Additional fields
    associated_store_identifiers: Optional[list] = None
    app_launch_url: Optional[str] = None
    user_info: Optional[dict] = None
    expiration_date: Optional[str] = None
    voided: Optional[bool] = None

    # Internal storage
    _files: Dict[str, bytes] = field(default_factory=dict)
    _hashes: Dict[str, str] = field(default_factory=dict)

    def add_file(self, name: str, file_data: Union[BytesIO, bytes]) -> None:
        """
        Add a file to be included in the pass package.

        Args:
            name: Name of the file in the pass
            file_data: File content as bytes or BytesIO
        """
        if isinstance(file_data, BytesIO):
            self._files[name] = file_data.read()
        else:
            self._files[name] = file_data

    def create(
        self,
        certificate: Union[str, Path],
        key: Union[str, Path],
        wwdr_certificate: Union[str, Path],
        password: Optional[str] = None,
        zip_file: Optional[BytesIO] = None,
    ) -> BytesIO:
        """
        Create and sign the pass package.

        Args:
            certificate: Path to the signing certificate
            key: Path to the private key
            wwdr_certificate: Path to the WWDR certificate
            password: Optional password for the private key
            zip_file: Optional BytesIO object to write to

        Returns:
            BytesIO object containing the signed .pkpass file
        """
        try:
            pass_json = self._create_pass_json()
            manifest = self._create_manifest(pass_json)
            signature = self._create_signature_crypto(
                manifest, certificate, key, wwdr_certificate, password
            )

            if not zip_file:
                zip_file = BytesIO()
            self._create_zip(pass_json, manifest, signature, zip_file=zip_file)
            return zip_file
        except Exception as e:
            raise PassCreationError(f"Failed to create pass: {str(e)}") from e

    def _read_file_bytes(self, path: Union[str, Path]) -> bytes:
        """Read file contents as bytes."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        with open(path, "rb") as f:
            return f.read()

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

    def json_dict(self) -> Dict[str, Any]:
        """Convert the pass to a dictionary suitable for JSON serialization."""
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

        # Handle barcode formats
        if self.barcode:
            original_formats = {
                BarcodeFormat.PDF417,
                BarcodeFormat.QR,
                BarcodeFormat.AZTEC,
            }
            legacy_barcode = self.barcode
            new_barcodes = [self.barcode.json_dict()]

            if self.barcode.format not in original_formats:
                legacy_barcode = Barcode(
                    message=self.barcode.message,
                    format=BarcodeFormat.PDF417,
                    alt_text=self.barcode.altText,
                )
            d.update({"barcodes": new_barcodes, "barcode": legacy_barcode})

        # Add optional fields if they exist
        optional_fields = {
            "relevantDate": self.relevant_date,
            "backgroundColor": self.background_color,
            "foregroundColor": self.foreground_color,
            "labelColor": self.label_color,
            "logoText": self.logo_text,
            "locations": self.locations,
            "beacons": self.ibeacons,
            "userInfo": self.user_info,
            "associatedStoreIdentifiers": self.associated_store_identifiers,
            "appLaunchURL": self.app_launch_url,
            "expirationDate": self.expiration_date,
        }

        d.update({k: v for k, v in optional_fields.items() if v is not None})

        if self.voided:
            d["voided"] = True

        if self.web_service_url:
            d.update(
                {
                    "webServiceURL": self.web_service_url,
                    "authenticationToken": self.authentication_token,
                }
            )

        return d


class PassCreationError(Exception):
    """Raised when there is an error creating the pass."""

    pass


def pass_handler(obj: Any) -> Any:
    """JSON serialization handler for pass objects."""
    if hasattr(obj, "json_dict"):
        return obj.json_dict()
    if isinstance(obj, decimal.Decimal):
        return str(obj)
    return obj
