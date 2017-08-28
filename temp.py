import kerberos
import requests


class KerberosTicket:

    def __init__(self, service):
        __, krb_context = kerberos.authGSSClientInit(service)
        kerberos.authGSSClientStep(krb_context, "")
        self._krb_context = krb_context
        self.auth_header = ("Negotiate " +
        kerberos.authGSSClientResponse(krb_context))

    def verify_response(self, auth_header):
        for field in auth_header.split(","):
            kind, __, details = field.strip().partition(" ")
            if kind.lower() == "negotiate":
                auth_details = details.strip()
                break
            else:
                raise ValueError("Negotiate not found in %s" % auth_header)
        krb_context = self._krb_context
        if krb_context is None:
            raise RuntimeError("Ticket already used for verification")
        self._krb_context = None
        kerberos.authGSSClientStep(krb_context, auth_details)
        kerberos.authGSSClientClean(krb_context)


krb = KerberosTicket("HTTP@10.16.0.64")
headers = {"Authorization": krb.auth_header}
r = requests.get("https://10.16.0.64/LogRhythm.API/Services/LookupServiceWindowsAuth.svc", headers=headers)
krb.verify_response(r.auth_headerheaders["www-authenticate"])
print r.text
