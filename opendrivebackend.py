import os

from duplicity import backend
from duplicity import log
from duplicity.errors import BackendException
import urllib2
import json
from os import path


class OpenDriveBackend(backend.Backend):
    """
    Backend to access OpenDrive storage services
    Contributed in 2016 by Marc Vollmer <admin@vmtek.de>
    """

    def __init__(self, parsed_url):
        backend.Backend.__init__(self, parsed_url)
        self.parsed_url = parsed_url
        self.username = parsed_url.username
        self.password = self.get_password()
        self.directory = parsed_url.path.replace("/", "")
        if self.directory == "":
            self.directory = "0"

        self.baseurl = "https://dev.opendrive.com/api/v1/"

        self.sessionid = None
        self.retry = 0
        self.chunkretry = 0
        self.closeretry = 0
        self.uploadretry = 0

        log.Info("Using OpenDrive Backend with directory ID %s" % self.directory)

    def __dopostrequest(self, url, postobject):
        """
        Do a Post Request
        :param url: URL to POST to
        :param postobject: Object to POST (will be encoded as JSON)
        :return: Response Object
        """
        postdata = json.dumps(postobject).encode('utf8')

        req = urllib2.Request(url, data=postdata, headers={'content-type': 'application/json'})
        req.get_method = lambda: 'POST'
        return urllib2.urlopen(req)

    def __dogetrequest(self, url):
        """
        Go a Get Request
        :param url: URL to GET
        :return: Response Object
        """
        req = urllib2.Request(url)
        req.get_method = lambda: 'GET'
        return urllib2.urlopen(req)

    def __decodejson(self, data):
        """
        Decode a JSON Object
        :param data: Byte Data
        :return: JSON Object
        """
        strdata = data.decode('utf8')
        return json.loads(strdata)

    def __getfileidfromname(self, filename):
        """
        Get the File ID from the Filename
        :param filename: Filename
        :return: File ID (None if not found)
        """
        try:
            self.login()
            log.Info("Load File ID for Filename: %s" % filename)

            listurl = self.baseurl + "folder/itembyname.json/" + self.sessionid + "/" + self.directory + "?name=" + filename

            resp = self.__dogetrequest(listurl)
            status = resp.getcode()
            if status == 401:
                log.Warn("Session expired")
                self.login(forced=True)
                return self.__getfileidfromname(filename)
            elif status != 200:
                log.FatalError("Failed to list files in directory %s to get file id for file %s , API Returned Status: %d" % (self.directory, filename, status))
                return None
            else:
                self.retry = 0

            data = resp.read()
            directoryinfo = self.__decodejson(data)
            for fileinfo in directoryinfo["Files"]:
                if fileinfo["Name"] == filename:
                    return fileinfo["FileId"]

            return None
        except urllib2.HTTPError as e:
            if e.code == 401:
                log.Warn("Session expired")
                self.login(forced=True)
                return self.__getfileidfromname(filename)
            else:
                log.FatalError("Failed to list files in directory %s to get file id for file %s , API Returned Status: %d" % (self.directory, filename, e.code))
                return None
        except not BackendException:
            log.Warn("Error loading file id from filename for %s" % filename)
            return None

    def _list(self):
        """
        Return list of filenames (byte strings) present in backend
        """
        try:
            self.login()
            log.Info("Listing files in directory %s" % self.directory)

            listurl = self.baseurl + "folder/list.json/" + self.sessionid + "/" + self.directory

            resp = self.__dogetrequest(listurl)
            status = resp.getcode()
            if status == 401:
                log.Warn("Session expired")
                self.login(forced=True)
                return self._list()
            elif status != 200:
                log.FatalError("Failed to list files in directory %s, API Returned Status: %d" % (self.directory, status))
                raise BackendException("Failed to list files in directory %s, API Returned Status: %d" % (self.directory, status))
            else:
                self.retry = 0

            data = resp.read()
            directoryinfo = self.__decodejson(data)
            files = []
            for fileinfo in directoryinfo["Files"]:
                files.append(fileinfo["Name"])
            return files
        except urllib2.HTTPError as e:
            if e.code == 401:
                log.Warn("Session expired")
                self.login(forced=True)
                return self._list()
            else:
                log.FatalError("Failed to list files in directory %s, API Returned Status: %d" % (self.directory, e.code))
                raise BackendException("Failed to list files in directory %s, API Returned Status: %d" % (self.directory, e.code))
        except not BackendException:
            log.FatalError("Error listing files in directory %s" % self.directory)
            raise BackendException("Error listing files in directoy %s" % self.directory)

    def get(self, remote_filename, local_path):
        """Retrieve remote_filename and place in local_path"""
        try:
            self.login()
            log.Info("Downloading %s to %s" % (remote_filename, local_path))

            fileid = self.__getfileidfromname(remote_filename)
            if not fileid:
                log.FatalError("File %s not found" % remote_filename)
                raise BackendException("File %s not found" % remote_filename)

            downloadurl = self.baseurl + "download/file.json/" + fileid + "?session_id=" + self.sessionid

            resp = self.__dogetrequest(downloadurl)
            status = resp.getcode()
            if status == 401:
                log.Warn("Session expired")
                self.login(forced=True)
                return self.get(remote_filename, local_path)
            elif status != 200:
                log.FatalError("Error downloading remote file %s to local path %s" % (remote_filename, local_path))
                raise BackendException("Error downloading remote file %s to local path %s" % (remote_filename, local_path))
            else:
                self.retry = 0

            f = open(local_path, mode="w")
            f.write(resp.read())
            f.close()
        except urllib2.HTTPError as e:
            if e.code == 401:
                log.Warn("Session expired")
                self.login(forced=True)
                return self.get(remote_filename, local_path)
            else:
                log.FatalError("Error downloading remote file %s to local path %s" % (remote_filename, local_path))
                raise BackendException("Error downloading remote file %s to local path %s" % (remote_filename, local_path))
        except not BackendException:
            log.FatalError("Error downloading remote file %s to local path %s" % (remote_filename, local_path))
            raise BackendException("Error downloading remote file %s to local path %s" % (remote_filename, local_path))

    def put(self, source_path, remote_filename=None):
        """
        Transfer source_path (Path object) to remote_filename (string)

        If remote_filename is None, get the filename from the last
        path component of pathname.
        """
        try:
            self.login()
            log.Info("Upload %s to %s" % (source_path, remote_filename))

            if not remote_filename:
                remote_filename = path.basename(source_path)
                log.Info("Set remote Filename to %s" % remote_filename)

            srcfile = open(source_path, "r")
            size = path.getsize(source_path)

            fileid = self.__createfile(remote_filename, size)
            log.Info("File ID: %s" % fileid)

            tmplocation = self.__openfileupload(fileid, size)
            log.Info("Temp Location: %s" & tmplocation)
        except not BackendException:
            log.FatalError("Error uploading file %s" % source_path)
            raise BackendException("Error uploading file %s" % source_path)

    def __createfile(self, filename, filesize):
        """
        Create the new file on OpenDrive and get the File ID
        :param filename: remote filename
        :param filesize: size of the file in bytes
        :return: File ID
        """
        try:
            self.login()
            log.Info("Create remote file %s with size %d" % (filename, filesize))

            createfileurl = self.baseurl + "upload/create_file.json"
            createfiledata = {"session_id": self.sessionid, "folder_id": self.directory, "file_name": filename, "file_size": filesize, "access_folder_id": "", "open_existing": "false"}

            resp = self.__dopostrequest(createfileurl, createfiledata)
            status = resp.getcode()

            if status == 401:
                log.Warn("Session expired")
                self.login(forced=True)
                return self.__createfile(filename, filesize)
            elif status != 200:
                log.FatalError("Error creating remote file %s with size %d (API returned %d)" % (filename, filesize, status))
                raise BackendException("Error creating remote file %s with size %d (API returned %d)" % (filename, filesize, status))
            else:
                self.retry = 0

            data = resp.read()
            createfileinfo = self.__decodejson(data)
            return createfileinfo["FileId"]
        except urllib2.HTTPError as e:
            if e.code == 401:
                log.Warn("Session expired")
                self.login(forced=True)
                return self.__createfile(filename, filesize)
            else:
                log.FatalError("Error creating remote file %s with size %d (API returned %d)" % (filename, filesize, e.code))
                raise BackendException("Error creating remote file %s with size %d (API returned %d)" % (filename, filesize, e.code))
        except not BackendException:
            log.FatalError("Error creating remote file %s with size %d" % (filename, filesize))
            raise BackendException("Error creating remote file %s with size %d" % (filename, filesize))

    def __openfileupload(self, fileid, size):
        """
        Open a new File Upload
        :param size: Filesize
        :return: Temp Location
        """
        try:
            log.Info("Open file upload for file %s with size %d" % (fileid, size))

            openfileuplurl = self.baseurl + "upload/open_file_upload.json"
            openfileupldata = {"session_id": self.sessionid, "file_id": fileid, "file_size": size, "access_folder_id": ""}

            resp = self.__dopostrequest(openfileuplurl, openfileupldata)
            status = resp.getcode()

            if status == 401:
                log.Warn("Session expired")
                self.login(forced=True)
                return self.__openfileupload(fileid, size)
            elif status != 200:
                log.FatalError("Error opening file upload for dile %s with size %d (API returned %d)" % (fileid, size, status))
                raise BackendException("Error opening file upload for dile %s with size %d (API returned %d)" % (fileid, size, status))
            else:
                self.retry = 0

            data = resp.read()
            openfileuplinfo = self.__decodejson(data)
            return openfileuplinfo["TempLocation"]
        except urllib2.HTTPError as e:
            if e.code == 401:
                log.Warn("Session expired")
                self.login(forced=True)
                return self.__openfileupload(fileid, size)
            else:
                log.FatalError("Error opening file upload for dile %s with size %d (API returned %d)" % (fileid, size, e.code))
                raise BackendException("Error opening file upload for dile %s with size %d (API returned %d)" % (fileid, size, e.code))
        except not BackendException:
            log.FatalError("Error opening file upload for dile %s with size %d" % (fileid, size))
            raise BackendException("Error opening file upload for dile %s with size %d" % (fileid, size))

    def __upload(self, srcfile, size, fileid):
        """
        Upload the file
        :param srcfile: Source File
        :param size: Filesize
        :param fileid: File ID
        """


    def delete(self, filename_list):
        """
        Delete each filename in filename_list, in order if possible.
        """
        try:
            self.login()
            log.Info("Delete files")

            deleteurl = self.baseurl + "file/trash.json"

            for filename in filename_list:
                try:
                    log.Info("Delete file: %s" % filename)
                    fileid = self.__getfileidfromname(filename)
                    if not fileid:
                        pass

                    deletedata = {"session_id": self.sessionid, "file_id": fileid}

                    resp = self.__dopostrequest(deleteurl, deletedata)
                    status = resp.getcode()
                    if status == 401:
                        log.Warn("Session expired")
                        self.login(forced=True)
                        return self.delete(filename_list)
                    elif status != 200:
                        log.FatalError("Failed to delete file %s in directory %s, API Returned Status: %d" % (filename, self.directory, status))
                        pass
                    else:
                        self.retry = 0
                except not BackendException:
                    log.FatalError("Error deleting file %s" % filename)
                    raise BackendException("Error deleting file %s" % filename)
        except not BackendException:
            log.FatalError("Error deleting files")
            raise BackendException("Error deleting files")

    def _query_file_info(self, filename):
        """
        Return metadata about file

        Supported metadata are:
        'size': if >= 0, size of file
                if -1, file is not found
                if None, error querying file
        """
        try:
            self.login()
            log.Info("Load File Size for Filename: %s" % filename)

            listurl = self.baseurl + "folder/itembyname.json/" + self.sessionid + "/" + self.directory + "?name=" + filename

            resp = self.__dogetrequest(listurl)
            status = resp.getcode()
            if status == 401:
                log.Warn("Session expired")
                self.login(forced=True)
                return self.__getfileidfromname(filename)
            elif status != 200:
                log.FatalError("Failed to list files in directory %s to get file size for file %s , API Returned Status: %d" % (self.directory, filename, status))
                return {"size": -1}
            else:
                self.retry = 0

            data = resp.read()
            directoryinfo = self.__decodejson(data)
            for fileinfo in directoryinfo["Files"]:
                if fileinfo["Name"] == filename:
                    return {"size": fileinfo["Size"]}

            return {"size": -1}
        except urllib2.HTTPError as e:
            if e.code == 401:
                log.Warn("Session expired")
                self.login(forced=True)
                return self.__getfileidfromname(filename)
            else:
                log.FatalError("Failed to list files in directory %s to get file size for file %s , API Returned Status: %d" % (self.directory, filename, e.code))
                return {"size": -1}
        except not BackendException:
            log.Warn("Error loading file id from filename for %s" % filename)
            return {"size": None}

    def login(self, forced=False):
        """
        Login to OpenDrive
        """
        try:
            if not self.sessionid or forced:
                self.close()

                if forced:
                    if self.retry >= 5:
                        log.FatalError("Login Retry Limit of 5 reached")
                        raise BackendException("Login Retry Limit of 5 reached")
                    else:
                        self.retry += 1

                log.Info("Logging in to OpenDrive")

                loginurl = self.baseurl + "session/login.json"
                logindata = {"username": self.username, "passwd": self.password}

                resp = self.__dopostrequest(loginurl, logindata)
                status = resp.getcode()
                if status != 200:
                    log.FatalError("Login failed, API returned Status code: %d" % status)
                    raise BackendException("Error logging in to OpenDrive. API Returned Status %d" % status)

                data = resp.read()
                userinfo = self.__decodejson(data)
                self.sessionid = userinfo["SessionID"]
        except not BackendException:
            log.FatalError("Failed to login to OpenDrive")
            raise BackendException("Error logging in to OpenDrive")

    def close(self):
        """
        Close the backend, releasing any resources held and
        invalidating any file objects obtained from the backend.
        """
        try:
            if self.sessionid:
                log.Info("Logout")

                logouturl = self.baseurl + "session/logout.json"
                logoutdata = {"session_id": self.sessionid}

                resp = self.__dopostrequest(logouturl, logoutdata)
                status = resp.getcode()
                if status != 200:
                    log.Warn("Logout failed, API Returned Status Code: %d" % status)

            self.sessionid = None
            self.retry = 0
            self.chunkretry = 0
            self.closeretry = 0
            self.uploadretry = 0
        except not BackendException:
            log.Warn("Logout failed")


backend.register_backend("opendrive", OpenDriveBackend)
