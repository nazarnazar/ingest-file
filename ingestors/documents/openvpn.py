from followthemoney import model

from ingestors.ingestor import Ingestor
from ingestors.support.encoding import EncodingSupport
from ingestors.exc import ProcessingException
from ingestors.support.temp import TempFileSupport

from normality import safe_filename

import re
import pathlib

class OpenVpnIngestor(Ingestor, EncodingSupport, TempFileSupport):
    """OpenVPN file ingestor class."""

    MIME_TYPES = []
    EXTENSIONS = ["ovpn"]
    MAX_SIZE = 4 * 1024 * 1024
    SCORE = 2

    def ingest(self, file_path, entity):
        """Ingestor implementation."""
        entity.schema = model.get("OpenVpn")
        for file_size in entity.get("fileSize"):
            if int(file_size) > self.MAX_SIZE:
                raise ProcessingException("Text file is too large.")

        text = self.read_file_decoded(entity, file_path)
        entity.set("bodyText", text)

        parsed_config = self.parse_openvpn_config(file_path)
        for key, value in parsed_config.items():
            entity.add(key, value)

        self.ingest_cert(entity, "cert-test-1", "text/plain", "cert-body-1")

    def parse_openvpn_config(self, filename):
        config = {}
        with open(filename, 'r') as file:
            for line in file:
                # Extract server domain name
                match = re.match(r'^remote\s+([\w.-]+)\s+(\d+)', line)
                if match:
                    config['serverDomain'] = match.group(1)
                    config['serverPort'] = match.group(2)
                
                # Extract network address
                match = re.match(r'^server\s+([\d.]+)\s+([\d.]+)', line)
                if match:
                    config['networkAddress'] = match.group(1)
                    config['subnetMask'] = match.group(2)
                
                # Extract certificates
                # match = re.match(r'^(ca|cert|key)\s+(.*)', line)
                # if match:
                #     cert_type = match.group(1)
                #     cert_path = match.group(2)
                #     config[cert_type + '_file'] = cert_path.strip()
                #     with open(cert_path.strip(), 'r') as cert_file:
                #         config[cert_type + '_content'] = cert_file.read()
                
                # Extract passwords (tls-auth)
                # match = re.match(r'^tls-auth\s+(.*)\s+(\d+)', line)
                # if match:
                #     config['tls_auth_file'] = match.group(1)
                #     with open(match.group(1), 'r') as auth_file:
                #         config['tls_auth_content'] = auth_file.read()
        
        return config
    
    def ingest_cert(self, entity, name, mime_type, body):
        foreign_id = pathlib.PurePath(entity.id)
        folder_name = "certificates"
        foreign_id = foreign_id.joinpath(folder_name)
        folder_entity = self.manager.make_entity("Folder", parent=entity)
        folder_entity.add("fileName", folder_name)
        folder_entity.make_id(foreign_id.as_posix())
        self.manager.emit_entity(folder_entity)
        
        file_name = safe_filename(name, default="cert-1")
        file_path = self.make_work_file(file_name)
        with open(file_path, "wb") as fh:
            if isinstance(body, str):
                body = body.encode("utf-8")
            if body is not None:
                fh.write(body)

        checksum = self.manager.store(file_path, mime_type=mime_type)
        file_path.unlink()

        child = self.manager.make_entity("Document", parent=folder_entity)
        child.make_id(name, checksum)
        child.add("contentHash", checksum)
        child.add("fileName", name)
        child.add("mimeType", mime_type)
        self.manager.queue_entity(child)