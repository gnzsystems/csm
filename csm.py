import os
import re
import sys
import time
import uuid
import json
import base64
import sqlite3
import win32con
import win32api
import threading
import subprocess
import wincertstore
import _winreg as reg
from hashlib import sha1
from time import strftime
from hashlib import sha256
from pyasn1_modules import rfc2459
import win32com.shell.shell as shell
from pyasn1.codec.der import decoder


"""

The MIT License (MIT)

Copyright (c) 2016 GNZ Systems and Consulting, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Software written by Jeff Gonzalez of GNZ Systems and Consulting, Inc.

"""

class CertificateStoreManager:

    def __init__(self, logCallback):
        MSstore = r"Software\Microsoft\SystemCertificates"
        GPstore = r"Software\Policy\Microsoft\SystemCertificates"
        self.regKeys = {
            "CU_STORE": [reg.HKEY_CURRENT_USER, MSstore],
            "LM_STORE": [reg.HKEY_LOCAL_MACHINE, MSstore],
            "USER_STORE": [reg.HKEY_USERS, MSstore],
            "CU_POLICY_STORE": [reg.HKEY_CURRENT_USER, GPstore],
            "LM_POLICY_STORE": [reg.HKEY_LOCAL_MACHINE, GPstore]
        }
        self.logCallback = logCallback

    def read_registry(self):
        keyHashes = {}
        for key in self.regKeys:
            self._log("Reading registry data from key: %s" % key)
            certData = {}
            try:
                self._log("Connecting to: %s" % key)
                hive = reg.ConnectRegistry(None, self.regKeys[key][0])
                regKey = reg.OpenKey(hive, self.regKeys[key][1])
                i = 0
                self._log("Enumerating key: %s" % key)
                while True:
                    try:
                        subkey_name = reg.EnumKey(regKey, i)
                        self._log("Found subkey: %s" % subkey_name)
                        a_subkey = reg.OpenKey(regKey, subkey_name)
                        certs = {}
                        try:
                            a_subkey_certKey = reg.OpenKey(a_subkey, "Certificates")
                            n = 0
                            self._log("Enumerating certificate store: %s/Certificates" % subkey_name)
                            while True:
                                try:
                                    certKey_name = reg.EnumKey(a_subkey_certKey, n)
                                    self._log("Found certificate: %s" % certKey_name)
                                    certKey = reg.OpenKey(a_subkey_certKey, certKey_name)
                                    blob = reg.QueryValueEx(certKey, "Blob")[0]
                                    keyHash = self._hash(blob)
                                    certs[certKey_name] = {
                                        "hash": keyHash,
                                        "blob": base64.b64encode(blob),
                                        "path": "/".join([key, subkey_name, "Certificates", certKey_name])
                                    }
                                    reg.CloseKey(certKey)
                                    n += 1
                                except EnvironmentError:
                                    break
                            self._log("Closing cert store: %s/Certificates" % subkey_name)
                            reg.CloseKey(a_subkey_certKey)
                        except EnvironmentError:
                            pass
                        reg.CloseKey(a_subkey)
                        for certName in certs:
                            try:
                                certData[subkey_name][certName] = certs[certName]
                            except KeyError:
                                certData[subkey_name] = {certName: certs[certName]}
                        try:
                            self._log("Stored %d hash values for subkey: %s" % (len(certData[subkey_name]),
                                                                                subkey_name))
                        except KeyError:
                            self._log("No keys stored for subkey: %s" % subkey_name)
                        i += 1
                    except EnvironmentError:
                        self._log("Storing final values for key: %s" % key)
                        keyHashes[key] = certData
                        self._log("Closing key: %s" % key)
                        reg.CloseKey(regKey)
                        self._log("Closing registry handle for key: %s" % key)
                        reg.CloseKey(hive)
                        break
            except WindowsError:
                self._log("Unable to open key: %s" % key)
                pass
        self._log("All registry operations completed.")
        return keyHashes

    def read_subkeys(self, regKey):
        self._log("Reading subkeys for registry key: %s" % regKey)
        registryHandles = []
        subkeys = []
        path = regKey.split("/")
        hiveName = path.pop(0)
        hive = reg.ConnectRegistry(None, self.regKeys[hiveName][0])
        registryHandle = reg.OpenKey(hive, self.regKeys[hiveName][1])
        registryHandles.append(hive)
        self._log("Connected to registry at location: %s" % hiveName)
        for step in path:
            registryHandles.append(registryHandle)
            registryHandle = reg.OpenKey(registryHandle, step)
        i = 0
        while True:
            try:
                subkey = reg.EnumKey(registryHandle, i)
                self._log("Found subkey: %s" % subkey)
                subkeys.append(subkey)
                i += 1
            except EnvironmentError:
                break
        self._log("Found %d subkeys." % len(subkeys))
        self._log("Closing %d registry handles..." % len(registryHandles))
        for handle in registryHandles:
            reg.CloseKey(handle)
        self._log("Done. Subkey enumeration completed.")
        return subkeys

    def read_cryptoapi(self):
        certData = {}
        self._log("Retrieving certificate data from CryptoAPI")
        for storename in ("CA", "ROOT", "MY"):
            self._log("Gathering information from store: %s" % storename)
            with wincertstore.CertSystemStore(storename) as store:
                storecerts = {}
                for cert in store.itercerts(usage=None):
                    certName = cert.get_name()
                    self._log("Processing certificate: %s" % certName)
                    keyName = re.sub(r"[\W]+", '', cert.get_name())
                    pem = cert.get_pem().decode("ascii")
                    encodedDer = ''.join(pem.split("\n")[1:-2])
                    der = base64.b64decode(encodedDer)
                    h = sha1()
                    h.update(der)
                    thumbprint = h.hexdigest()
                    certificateInfo = {
                        "Name": certName,
                        "Thumbprint": thumbprint,
                        "PEM": pem
                    }
                    self._log("Processing DER data for certificate: %s" % certName)
                    derInfo = self._parse_der(der)
                    for key in derInfo:
                        certificateInfo[key] = derInfo[key]
                    storecerts[keyName] = certificateInfo
                    self._log("Finished processing certificate: %s" % certName)
            certData[storename] = storecerts
        return certData

    def get_unknown_certificate(self, thumbprint):
        certData = self.read_cryptoapi()
        for storeName in certData:
            for certificate in certData[storeName]:
                if certData[storeName][certificate]["Thumbprint"].upper() == thumbprint:
                    return certData[storeName][certificate]
        return False

    def remove_certificate(self, certificate):
        CONTAINS_SUBKEYS = 0
        registryHandles = []
        returnValue = False
        path = certificate["RegPath"].split("/")
        hiveName = path.pop(0)
        keyName = path.pop(-1)
        hive = reg.ConnectRegistry(None, self.regKeys[hiveName][0])
        registryHandle = reg.OpenKey(hive, self.regKeys[hiveName][1])
        self._log("Connected to registry at location: %s" % hiveName)
        for step in path:
            registryHandles.append(registryHandle)
            registryHandle = reg.OpenKey(registryHandle, step)
        try:
            deletionCandidate = reg.OpenKey(registryHandle, keyName)
            self._log("Querying deletion canditate: %s" % certificate["RegPath"])
            if not reg.QueryInfoKey(deletionCandidate)[CONTAINS_SUBKEYS]:
                self._log("Attempting to delete key: %s" % certificate["RegPath"])
                reg.CloseKey(deletionCandidate)
                reg.DeleteKey(registryHandle, keyName)
                self._log("Deleted key: %s" % certificate["RegPath"])
                returnValue = True
            else:
                self._error_log("Unable to delete key: %s.  Key  contains subkeys." % certificate["RegPath"])
                registryHandles.append(deletionCandidate)
                raise WindowsError
        except WindowsError as e:
            self._error_log("Unable to delete key: %s.  Windows error." % certificate["RegPath"])
            self._error_log("%s: %s" % (certificate["RegPath"], str(e)))
            pass
        self._log("Closing registry handles...")
        for handle in registryHandles:
            reg.CloseKey(handle)
        reg.CloseKey(hive)
        self._log("Registry handles closed.")
        return returnValue

    def _parse_der(self, der):
        sequences = [
            "issuer",
            "validity",
            "subject"
        ]
        infoMap = {
            "2.5.4.10": "Organization",
            "2.5.4.11": "OU",
            "2.5.4.6": "Country",
            "2.5.4.3": "CN"
        }
        certificateInfo = {}
        cert = decoder.decode(der, asn1Spec=rfc2459.Certificate())[0]
        cert = cert["tbsCertificate"]
        for sequence in sequences:
            rdnsequence = cert[sequence][0]
            for rdn in rdnsequence:
                if not rdn:
                    continue
                if len(rdn[0]) > 1:
                    oid, value = rdn[0]
                    oid = str(oid)
                    value = ''.join(re.findall(r"[A-Za-z0-9\.\s]+", str(value)))
                    try:
                        if not infoMap[oid] == "Type":
                            certificateInfo[infoMap[oid]] = value
                        else:
                            try:
                                certificateInfo[infoMap[oid]] += ", %s" % value
                            except KeyError:
                                certificateInfo[infoMap[oid]] = value
                    except KeyError:
                        pass
                else:
                    try:
                        certificateInfo["Valid"] += ", %s" % str(rdn)
                    except KeyError:
                        certificateInfo["Valid"] = str(rdn)
        return certificateInfo

    def _error_log(self, msg):
        self.logCallback(msg, messageType="ERROR")

    def _log(self, msg):
        self.logCallback(msg)

    @staticmethod
    def _hash(keyData):
        h = sha256()
        h.update(str(keyData))
        return h.hexdigest()


class DatabaseEngine:

    def __init__(self, logCallback):
        self.logCallback = logCallback
        self.home = os.path.dirname(os.path.realpath(__file__))
        self.dbFile = os.path.join(self.home, "certificates.db")
        self.database = self._open_database()
        self.queries = []

    def close(self):
        self.database["cursor"].close()
        self.database["handle"].commit()
        self.database["handle"].close()

    def run_query(self, preparedQuery, queryInfo=None):
        try:
            if not queryInfo:
                self.database["cursor"].execute(preparedQuery)
            else:
                if (type(queryInfo) == str) or (type(queryInfo) == unicode):
                    queryInfo = (queryInfo,)
                self.database["cursor"].execute(preparedQuery, queryInfo)
            result = self.database["cursor"].fetchall()
            self.database["handle"].commit()
            if not result:
                return True
            else:
                return result
        except sqlite3.Error as e:
            self._error_log("Database Error: %s" % str(e))
            return False

    def run_query_batch(self):
        self._log("Batch executing %d queries..." %  len(self.queries))
        for query in self.queries:
            if (type(query[1]) == str) or (type(query[1]) == unicode):
                query[1] = (query[1],)
            try:
                self.database["cursor"].execute(query[0], query[1])
            except sqlite3.Error as e:
                self._error_log("Database Error: %s" % str(e))
                continue
        self.database["handle"].commit()
        self._log("Committing database changes...")
        return True

    def queue_query(self, preparedQuery, queryInfo):
        self.queries.append([preparedQuery, queryInfo])

    def get_watch_keys(self):
        keys = []
        result = self.run_query("SELECT path FROM registry")
        if not type(result) == bool:
            for line in result:
                line = line[0].split("/")
                line.pop(-1)
                watchKey = "/".join(line)
                if not watchKey in keys:
                    keys.append(watchKey)
        return keys

    def certificate_is_known(self, thumbprint):
        query = "SELECT * FROM %s WHERE thumbprint=? LIMIT 1"
        tables = [
            "registry",
            "cryptoapi"
        ]
        for table in tables:
            result = self.run_query(query % table, thumbprint)
            if not type(result) == bool:
                return True
        return False

    def certificate_is_active(self, thumbprint):
        result = self.run_query("SELECT status FROM registry WHERE thumbprint=? LIMIT 1", thumbprint)
        if not type(result) == bool:
            if not result[0][0] == -1:
                return True
        return False

    def get_certificate(self, thumbprint):
        result = {}
        query = "SELECT * FROM %s WHERE thumbprint=?"
        tables = [
            "registry",
            "cryptoapi"
        ]
        for table in tables:
            queryResult = self.run_query(query % table, thumbprint)
            if type(queryResult) == list:
                result[table] = queryResult
        return result

    def set_certificate_inactive(self, path, thumbprint):
        self.queue_query("UPDATE registry SET status=-1 WHERE path=?", path)
        self.queue_query("UPDATE cryptoapi SET status=-1 WHERE thumbprint=?", thumbprint)
        self.run_query_batch()
        return True

    def correlate_tables(self):
        self._log("Correlating database tables...")
        regResult = self.run_query("SELECT thumbprint FROM registry")
        for thumbprint in regResult:
            thumbprint = thumbprint[0]
            self._log("Checking thumbprint: %s" % thumbprint)
            apiResult = self.run_query("SELECT thumbprint FROM registry WHERE thumbprint=?", thumbprint)
            if apiResult:
                self._log("Thumbprint exists in both tables.  Queuing correlate flag change...")
                tables = ["registry", "cryptoapi"]
                for table in tables:
                    self.queue_query("UPDATE %s SET correlated=1 WHERE thumbprint=?" % table, thumbprint)
                """
                metaResult = self.run_query("SELECT thumbprint FROM meta WHERE thumbprint=?", thumbprint)
                if type(metaResult) == bool:
                    self.queue_query("INSERT INTO meta VALUES (?,?,?,?,?)", [thumbprint, 0, 1, 0, None])
                """
        if self.queries:
            self._log("Executing %d changes..." % len(self.queries))
            self.run_query_batch()
        self._log("Correlation finished!")
        return True

    def prepare_baseline_queries(self, registryInfo, apiInfo):
        regQuery = []
        apiQuery = []
        baseQuery = "INSERT INTO registry VALUES (?,?,?,?,?,?)"
        for registryHive in registryInfo:
            for activeStore in registryInfo[registryHive]:
                for thumbprint in registryInfo[registryHive][activeStore]:
                    if not self.certificate_is_known(thumbprint):
                        certificate = registryInfo[registryHive][activeStore][thumbprint]
                        queryData = [
                            thumbprint,
                            certificate["path"],
                            certificate["hash"],
                            certificate["blob"],
                            0,
                            0
                        ]
                        regQuery.append([baseQuery, queryData])
        baseQuery = "INSERT INTO cryptoapi VALUES (?,?,?,?,?,?,?,?,?,?)"
        requiredInfo = ["Thumbprint", "Name", "Organization", "OU", "CN", "Country", "Valid", "PEM"]
        for store in apiInfo:
            for certificate in apiInfo[store]:
                if not self.certificate_is_known(apiInfo[store][certificate]["Thumbprint"]):
                    preparedInfo = self._prepare_certificate_info(apiInfo[store][certificate], requiredInfo)
                    for i in range(2):
                        preparedInfo.append(0)
                    apiQuery.append([baseQuery, preparedInfo])
        queryContainers = [regQuery, apiQuery]
        i = 0
        for container in queryContainers:
            for query in container:
                self.queries.append(query)
                i += 1
        self._log("Prepared %d certificates for baseline." % i)
        return True

    def _open_database(self):
        self._log("Creating database handle...")
        if not os.path.isfile(self.dbFile):
            self._create_database()
        db = sqlite3.connect(self.dbFile)
        c = db.cursor()
        database = {
            "handle": db,
            "cursor": c
        }
        self._log("Handle created successfully!")
        return database

    def _create_database(self):
        if not os.path.isfile(self.dbFile):
            self._log("Database not found, creating...")
            db = sqlite3.connect(self.dbFile)
            c = db.cursor()
            c.execute("CREATE TABLE registry(thumbprint,path,hash,blob,status,correlated)")
            c.execute("CREATE TABLE cryptoapi(thumbprint,name,organization,ou,cn,country,valid,pem,status,correlated)")
            c.execute("CREATE TABLE meta(thumbprint,status,correlated,notify,message)")
            c.close()
            db.commit()
            db.close()
            self._log("Database created successfully!")
            return True
        else:
            self._log("Database already exists!")
            return False

    def _error_log(self, msg):
        self.logCallback(msg, messageType="ERROR")

    def _log(self, msg):
        self.logCallback(msg)

    @staticmethod
    def _prepare_certificate_info(certificateData, requiredInfo):
        preparedInfo = []
        for info in requiredInfo:
            if info in certificateData:
                preparedInfo.append(certificateData[info])
            else:
                preparedInfo.append(None)
        return preparedInfo


class SigCheckWrapper:

    def __init__(self):
        self.resources = os.path.join(os.path.dirname(os.path.realpath(__file__)), "resources")
        self.sigcheck = os.path.join(self.resources, "sigcheck.exe")
        self._validate()

    def check_store(self):
        storeNameRegex = re.compile(r"^.+[\\].+[:]$")
        certEndRegex = re.compile(r"^[V].+[o][:].+\d+[:]\d{2}.+[/]\d+[/]\d+.$")
        sc_process = subprocess.Popen([self.sigcheck, "-tv"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = sc_process.communicate()
        unapproved_certs = {}
        current_store = None
        current_cert = []
        for line in output.split("\n"):
            store_name = re.findall(storeNameRegex, line.rstrip("\r"))
            cert_end = re.findall(certEndRegex, line.strip())
            if store_name:
                current_store = store_name[0]
                unapproved_certs[current_store] = {}
            elif cert_end:
                if current_store:
                    current_cert.append(line)
                    cert_name = current_cert.pop(0)
                    unapproved_certs[current_store][cert_name] = current_cert
                    current_cert = []
            else:
                if current_store:
                    current_cert.append(line)
        return self._prepare_output(unapproved_certs)

    def _validate(self):
        if not os.path.isfile(self.sigcheck):
            sys.stderr.write("ERROR: Resource not found: %s" % self.sigcheck)
            sys.exit(1)

    @staticmethod
    def _prepare_output(output):
        certificates = {}
        for store in output:
            for certificate in output[store]:
                h = sha256()
                h.update(certificate)
                h.update(store)
                h.update(str(output[store][certificate]))
                certHandle = h.hexdigest()
                certificates[certHandle] = {
                    "Store": store.strip(),
                    "Name": certificate.strip(),
                }
                for certInfo in output[store][certificate]:
                    key, data = certInfo.split(":\t")
                    certificates[certHandle][key.strip()] = data.strip()
        return certificates


class BuiltInNotifier:

    def __init__(self):
        self.tempdir = os.path.join(os.environ["temp"], str(uuid.uuid4()))
        os.mkdir(self.tempdir)
        pass

    def confirm(self, msg):
        scriptPath = os.path.join(self.tempdir, "%s.vbs" % str(uuid.uuid4()))
        msgContent = msg["content"].replace("\n", '" & vbcrlf & "')
        script = [
            'result = MsgBox("%s", vbYesNo, "%s")' % (msgContent, msg["header"]),
            "exitCode = 0",
            "if result = vbYes Then exitCode = 1",
            "wscript.Quit(exitCode)"
        ]
        with open(scriptPath, "w") as outfile:
            for line in script:
                outfile.write("%s\n" % line)
        p = subprocess.Popen(["wscript.exe", scriptPath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.communicate()
        rc = p.returncode
        os.unlink(scriptPath)
        if rc == 1:
            return True
        else:
            return False

    def notify(self, msg):
        scriptPath = os.path.join(self.tempdir, "%s.vbs" % str(uuid.uuid4()))
        msgContent = msg["content"].replace("\n", '" & vbcrlf & "')
        script = [
            'result = MsgBox("%s", vbOKOnly, "%s")' % (msgContent, msg["header"]),
            "exitCode = 0",
            "if result = vbYes Then exitCode = 1",
            "wscript.Quit(exitCode)"
        ]
        with open(scriptPath, "w") as outfile:
            for line in script:
                outfile.write("%s\n" % line)
        p = subprocess.Popen(["wscript.exe", scriptPath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p.wait()
        os.unlink(scriptPath)
        return True


class WatchDog:

    def __init__(self, logCallback):
        self.csm = CertificateStoreManager(logCallback)
        self.database = DatabaseEngine(logCallback)
        self.notifier = BuiltInNotifier()
        self.sigcheck = SigCheckWrapper()
        self.logCallback = logCallback
        self.expect_change = False
        self.watchThreads = []
        self.changedKeys = []
        self.alive = False

    def establish_baseline(self):
        api = self.csm.read_cryptoapi()
        registry = self.csm.read_registry()
        self.database.prepare_baseline_queries(registry, api)
        self.database.run_query_batch()
        self.database.correlate_tables()
        return True

    def check_store(self):
        self._log("Checking for unauthorized certificates...")
        unauthorized_certificates = self.sigcheck.check_store()
        self._log("SigCheck wrapper returned successfully", messageType="DEBUG")
        if not len(unauthorized_certificates):
            self._log("No unauthorized certificates found.")
        else:
            self._log("Sending unauthorized certificates for removal.", messageType="DEBUG")
            self._certificate_removal_helper(unauthorized_certificates)
        self._log("SigCheck operations completed.")

    def _certificate_removal_helper(self, unauthorized_certificates):
        certificateInfo = [
            "Store",
            "Cert Issuer",
            "Name",
            "Serial Number",
            "Valid Usage",
            "Cert Status",
            "Valid from",
            "Valid to",
            "Thumbprint"
        ]
        for certificate in unauthorized_certificates:
            self._log("Checking info for certificate: %s" % unauthorized_certificates[certificate]["Name"])
            removalMessage = {
                "header": "CSM WatchDog",
                "content": "SigCheck has detected a certificate that is not in the default Windows store!\n\n"
                           "Certificate Info:\n\n"
            }
            for info in certificateInfo:
                if not len(info) < 9:
                    messageAddition = "%s:\t%s\n" % (info, unauthorized_certificates[certificate][info])
                else:
                    messageAddition = "%s:\t\t%s\n" % (info, unauthorized_certificates[certificate][info])
                removalMessage["content"] += messageAddition
            if self.database.certificate_is_known(unauthorized_certificates[certificate]["Thumbprint"]):
                self._log("CSM can remove this certificate! Notifying user.")
                removalMessage["content"] += "\nCSM has isolated this certificate and can remove it for you.\n\n"
                removalMessage["content"] += "Would you like to remove this certificate?"
                confirmation = self.notifier.confirm(removalMessage)
                if confirmation:
                    self._log("Removing certificate...")
                    self._remove_certificate(unauthorized_certificates[certificate])
            else:
                self._log("CSM is unable to remove this certificate.")
                removalMessage["content"] += "\nCSM was unable to isolate this certificate for you.\n\n"
                removalMessage["content"] += "Please use the Windows Certificate Manager to manually remove this " \
                                             "certificate"
                self.notifier.notify(removalMessage)

    def _remove_certificate(self, certificate):
        DB_THUMBPRINT = 0
        DB_PATH = 1
        storeNameMap = {
            "MACHINE": "LM_STORE",
            "CA": "Root",
            "USER": "CU_STORE"
        }
        notified = []
        removalSuccess = False
        tables = self.database.get_certificate(certificate["Thumbprint"])
        for table in tables:
            self._log("Checking table: %s" % table, messageType="DEBUG")
            for DB_CERT in tables[table]:
                self._log("Checking cert: %s" % DB_CERT[DB_THUMBPRINT], messageType="DEBUG")
                if self.database.certificate_is_active(DB_CERT[DB_THUMBPRINT]):
                    self._log("Certificate is active: %s" % DB_CERT[DB_THUMBPRINT], messageType="DEBUG")
                    store = certificate["Store"].split(":")[0].split("\\")
                    if store[1].upper() == "CA":
                        regStoreName = storeNameMap[store[1].upper()]
                        store[1] = "Root"
                    else:
                        regStoreName = storeNameMap[store[0].upper()]
                    self._log(regStoreName, messageType="DEBUG")
                    if regStoreName in DB_CERT[DB_PATH].split("/"):
                        self._log("Path validation First Step Complete.", messageType="DEBUG")
                        if store[1] not in DB_CERT[DB_PATH]:
                            if store[1] == "Root":
                                store[1] = "CA"
                        if store[1] in DB_CERT[DB_PATH]:
                            self._log("Path validation Second Step Complete.", messageType="DEBUG")
                            certificate["RegPath"] = DB_CERT[DB_PATH]
                            self._log("Removing certificate from registry...")
                            self.expect_change = True
                            removalSuccess = self.csm.remove_certificate(certificate)
                            self.expect_change = False
                            removalMessage = {
                                "header": "CSM Removal Activity",
                                "content": "No message yet..."
                            }
                            self._log("Certificate removed: %s" % removalSuccess, messageType="DEBUG")
                            if removalSuccess:
                                self._log("Certificate successfully removed!")
                                removalMessage["content"] = "Certificate removed successfully!"
                            else:
                                self._log("Unable to remove certficate.  Notifying user...")
                                removalMessage["content"] = "CSM was unable to remove the certificate. " \
                                                            "Please use the Windows Certificate Manager " \
                                                            "to manually remove it."
                            self._log("Checking if notification is necessary...", messageType="DEBUG")
                            h = sha256()
                            h.update(str(DB_CERT))
                            certHash = h.hexdigest()
                            if not certHash in notified:
                                self.notifier.notify(removalMessage)
                                notified.append(certHash)
                        else:
                            self._log(DB_CERT[DB_PATH])
        if removalSuccess:
            self._log("Setting certificate to 'Removed' in database.", messageType="DEBUG")
            self.database.set_certificate_inactive(certificate["RegPath"], certificate["Thumbprint"])
        self._log("Removal actions completed.")
        return removalSuccess

    def _watch_thread_dispatcher(self):
        MSstore = r"Software\Microsoft\SystemCertificates"
        GPstore = r"Software\Policy\Microsoft\SystemCertificates"
        regKeys = {
            "CU_STORE": [win32con.HKEY_CURRENT_USER, MSstore],
            "LM_STORE": [win32con.HKEY_LOCAL_MACHINE, MSstore],
            "USER_STORE": [win32con.HKEY_USERS, MSstore],
            "CU_POLICY_STORE": [win32con.HKEY_CURRENT_USER, GPstore],
            "LM_POLICY_STORE": [win32con.HKEY_LOCAL_MACHINE, GPstore]
        }
        watchKeys = self.database.get_watch_keys()
        for regKey in watchKeys:
            self._log("Dispatcher preparing watch thread for key: %s" % regKey, messageType="DEBUG")
            key = regKey.split("/")
            storeName = key.pop(0)
            additionalValue = "\\%s" % "\\".join(key)
            keystore = regKeys[storeName]
            keyName = keystore[1] + additionalValue
            t = threading.Thread(target=self._watch_thread, args=(keystore[0], keyName, regKey,
                                                                  self._watch_thread_callback,))
            self.watchThreads.append(t)
            self._log("Thread prepared.", messageType="DEBUG")
        self._log("Launching %d threads..." % len(self.watchThreads), messageType="DEBUG")
        for t in self.watchThreads:
            t.start()
        self._log("Dispatcher completed.", messageType="DEBUG")
        return

    def _watch_thread(self, hive, watchKey, name, callback):
        self._log("Watch thread active for key: %s" % name, messageType="DEBUG")
        while self.alive:
            watchHandle = win32api.RegOpenKey(hive, watchKey, 0, win32con.KEY_NOTIFY)
            win32api.RegNotifyChangeKeyValue(watchHandle, False, win32api.REG_NOTIFY_CHANGE_NAME, None, False)
            win32api.RegCloseKey(watchHandle)
            self._log("Change detected in thread: %s" % name, messageType="DEBUG")
            callback(name)
        self._log("Watch thread returning for key: %s" % name, messageType="DEBUG")
        return

    def _watch_thread_callback(self, regKey):
        if not self.expect_change:
            self._log("Unexpected change detected in registry key: %s" % regKey)
            self.changedKeys.append(regKey)
        else:
            self._log("Registry change detected, but it was expected.  Change ignored.", messageType="DEBUG")
        return

    def _registry_change_finder(self, watchKeys):
        baseline = self._get_registry_baseline(watchKeys)
        while self.alive:
            if self.changedKeys:
                key = self.changedKeys.pop(0)
                self._log("Searching for changes in key: %s" % key, messageType="DEBUG")
                subkeys = self.csm.read_subkeys(key)
                if len(baseline[key]) > len(subkeys):
                    for subkey in baseline[key]:
                        if subkey not in subkeys:
                            self._log("Certificate removed from registry.  Thumbprint: %s" % subkey)
                    baseline = self._get_registry_baseline(watchKeys)
                else:
                    for subkey in subkeys:
                        if subkey not in baseline[key]:
                            self._log("Certificate added to registry.  Thumbprint: %s" % subkey)
                            certificate = self.csm.get_unknown_certificate(subkey)
                            self._registry_change_handler(key, subkey, certificate)
                    baseline = self._get_registry_baseline(watchKeys)
            else:
                time.sleep(1)

    def _registry_change_handler(self, key, subkey, certificate=None):
        certificateInfo = [
            "Name",
            "Organization",
            "Country",
            "CN"
        ]
        notification = {
            "header": "CSM WatchDog: Change Detected",
            "content": "CSM WatchDog detected a new certificate in your certificate store.\n\n"
                       "Thumbprint: %s\n\n" % subkey
        }
        if certificate:
            notification["content"] += "Additional information (Gathered from Windows CryptoAPI): \n\n"
            for info in certificateInfo:
                if not len(info) < 9:
                    notification["content"] += "%s:\t" % info
                else:
                    notification["content"] += "%s:\t\t" % info
                try:
                    notification["content"] += "%s\n" % certificate[info]
                except KeyError:
                    notification["content"] += "Unavailable\n"
        else:
            notification["content"] += "Additional information unavailable from the Windows CryptoApi.\n\n"
        notification["content"] += "\nCSM has isolated this certificate and can remove it for you.\n\n" \
                                   "Would you like to remove this certificate?"
        confirmation = self.notifier.confirm(notification)
        if confirmation:
            key += "/%s" % subkey
            certificate["RegPath"] = key
            self.expect_change = True
            removalSuccess = self.csm.remove_certificate(certificate)
            self.expect_change = False
            notification = {
                "header": "CSM WatchDog: Certificate Removal",
                "content": "Nothing yet..."
            }
            if removalSuccess:
                notification["content"] = "Certificate removed successfully!"
            else:
                notification["content"] = "Unable to remove certificate.  Please remove it manually using the Windows" \
                                          "Certificate Manager."
            self.notifier.notify(notification)
        else:
            self._log("Ignoring certificate: %s" % key)

    def _get_registry_baseline(self, watchKeys):
        baseline = {}
        for key in watchKeys:
            subkeys = self.csm.read_subkeys(key)
            baseline[key] = subkeys
        return baseline

    def run(self, baselineEstablished=True):
        self._log("Initializing WatchDog...")
        self.alive = True
        if not baselineEstablished:
            self._log("Establishing certificate store baseline...")
            self.establish_baseline()
            self._log("Baseline established.")
        watchKeys = self.database.get_watch_keys()
        threads = [
            threading.Thread(target=self._registry_change_finder, args=(watchKeys,))
        ]
        self._log("WatchDog starting %d threads..." % len(threads), messageType="DEBUG")
        for t in threads:
            t.start()
        self._log("WatchDog starting watch thread dispatcher...", messageType="DEBUG")
        self._watch_thread_dispatcher()
        self._log("Running initial scan...")
        self.check_store()
        self._log("WatchDog Initialization completed.")
        return

    def exit(self):
        self._log("Stopping WatchDog...")
        self.alive = False
        self._log("Done.")
        return

    def _log(self, msg, messageType="WatchDog"):
        self.logCallback(msg, messageType)


class Core:

    def __init__(self, config):
        self.msgQueue = []
        self.logQueue = []
        self.basedir = os.path.dirname(os.path.realpath(__file__))
        self.config = config
        self.active = True

    def _centralized_logging(self, logfile):
        while self.active:
            if self.logQueue:
                msg = "%s\n" % self.logQueue.pop(0)
                with open(logfile, "a") as outfile:
                    outfile.write(msg)
        return

    def _centralized_stdout(self):
        while self.active:
            if self.msgQueue:
                msg = "%s\n" % self.msgQueue.pop(0)
                sys.stdout.write(msg)
        return

    def _flush_messages(self):
        self.log_callback("Flushing messages...")
        while self.msgQueue:
            pass
        while self.logQueue:
            pass
        self.log_callback("Done!")
        return

    def log_callback(self, msg, messageType="DEBUG"):
        if messageType == "DEBUG":
            if not self.config["log level"] == "DEBUG":
                return
        msg = "[%s] [%s] %s" % (strftime("%H:%M:%S | %d/%m/%Y"), messageType, msg)
        self.msgQueue.append(msg)
        self.logQueue.append(msg)
        return

    def run(self):
        self._elevate_permissions()
        logfile = os.path.join(self.basedir, self.config["log name"])
        threads = [
            threading.Thread(target=self._centralized_logging, args=(logfile,)),
            threading.Thread(target=self._centralized_stdout)
        ]
        for thread in threads:
            thread.start()
        return

    def exit(self):
        self._flush_messages()
        self.active = False

    @staticmethod
    def _elevate_permissions():
        f = sys.executable
        if not __file__.split("\\")[-1].split(".")[-1] == "py":
            f = __file__
            params = ' '.join(sys.argv[1:] + ["asadmin"])
        else:
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([script] + sys.argv[1:] + ['asadmin'])
        print params
        if not sys.argv[-1] == 'asadmin':
            shell.ShellExecuteEx(lpVerb='runas', lpFile=f, lpParameters=params)
            sys.exit(0)

if __name__ == "__main__":
    configFile = os.path.join(os.path.dirname(os.path.realpath(__file__)), "config.json")
    if os.path.isfile(configFile):
        with open(configFile, "r") as infile:
            config = json.loads(infile.read())
    else:
        config = {
            "log level": "Quiet",
            "log name": "log.txt",
            "baseline established": False
        }
    core = Core(config)
    watchdog = WatchDog(core.log_callback)
    core.run()
    watchdog.run(baselineEstablished=config["baseline established"])
    config["baseline established"] = True
    with open(configFile, "w") as outfile:
        outfile.write(json.dumps(config))
    core.log_callback("CSM Initialized successfully.")

