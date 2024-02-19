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

        certificates_folder_entity = self.ingest_folder(entity, 'certificates')

        parsed_config = self.parse_openvpn_config(file_path)
        properties = ''
        for key, value in parsed_config.items():
            if key == 'certificates':
                for certificate in value:
                    self.ingest_file(certificates_folder_entity, certificate['type'] + '.txt', "text/plain", certificate['content'])
            else:
                entity.add(key, value)
                properties += f"{key}: {value}\n"

        if properties != '':
            self.ingest_file(entity, 'properties.txt', "text/plain", properties)

    def parse_openvpn_config(self, filename):
        config = {}
        with open(filename, 'r') as file:
            current_cert_type = None
            current_cert_content = ""
            for line in file:
                # Extract server domain name and port
                match = re.match(r'^remote\s+([\w.-]+)\s+(\d+)', line)
                if match:
                    config['serverDomain'] = match.group(1)
                    config['serverPort'] = match.group(2)
                
                # Extract network address and subnet mask
                match = re.match(r'^server\s+([\d.]+)\s+([\d.]+)', line)
                if match:
                    config['networkAddress'] = match.group(1)
                    config['subnetMask'] = match.group(2)
                
                # Extract certificates, keys, and passwords (tls-auth)
                match = re.match(r'^(<ca>|<cert>|<key>|<tls-auth>)(?:\s+|$)(.*)', line)
                if match:
                    cert_type = match.group(1)[1:-1]
                    current_cert_type = cert_type
                    current_cert_content = ""
                
                # If current certificate type is set, append the line to its content
                if current_cert_type:
                    current_cert_content += line
                    if line.strip() == '</' + current_cert_type + '>':
                        # This line indicates end of certificate/key block
                        if 'certificates' not in config:
                            config['certificates'] = []
                        config['certificates'].append({'type': current_cert_type, 'content': current_cert_content})
                        current_cert_type = None
        
        return config
    
    def ingest_file(self, entity, name, mime_type, body):
        file_name = safe_filename(name, default="filename1")
        file_path = self.make_work_file(file_name)
        with open(file_path, "wb") as fh:
            if isinstance(body, str):
                body = body.encode("utf-8")
            if body is not None:
                fh.write(body)

        checksum = self.manager.store(file_path, mime_type=mime_type)
        file_path.unlink()

        child = self.manager.make_entity("Document", parent=entity)
        child.make_id(name, checksum)
        child.add("contentHash", checksum)
        child.add("fileName", name)
        child.add("mimeType", mime_type)
        self.manager.queue_entity(child)

    def ingest_folder(self, entity, name):
        foreign_id = pathlib.PurePath(entity.id)
        foreign_id = foreign_id.joinpath(name)
        folder_entity = self.manager.make_entity("Folder", parent=entity)
        folder_entity.add("fileName", name)
        folder_entity.make_id(foreign_id.as_posix())
        self.manager.emit_entity(folder_entity)
        return folder_entity