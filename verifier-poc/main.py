#!/usr/bin/env python3

import datetime

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization.base import Encoding
from cryptography.x509 import NameOID


class CAHierarchyBuilder:

    def __init__(self):
        pass

    def build(self):
        # Generate private keys
        rca_private_key = self.create_private_key()  # Root CA private key
        ica_private_key = self.create_private_key()  # Intermediate CA private key
        sica_private_key = self.create_private_key()  # Sub-intermediate CA private key
        ee_private_key = self.create_private_key()  # End-entity private key

        # Create certificates in hierarchy RCA -> ICA -> SICA -> EE
        rca = self.create_rca_cert(rca_private_key, outpath="rca.pem")
        ica = self.create_ica_cert(rca_private_key, ica_private_key, outpath="ica.pem")
        sica = self.create_sica_cert(ica_private_key, sica_private_key, outpath="sica.pem")
        ee = self.create_ee_cert(sica_private_key, ee_private_key, outpath="ee.pem")

        # Verify certificate signatures
        print("Verify certificate signatures ...")
        valid_signature = self.verify_certificate_signature(rca, rca_private_key.public_key())
        print(valid_signature)
        valid_signature = self.verify_certificate_signature(ica, rca_private_key.public_key())
        print(valid_signature)
        valid_signature = self.verify_certificate_signature(sica, ica_private_key.public_key())
        print(valid_signature)
        valid_signature = self.verify_certificate_signature(ee, sica_private_key.public_key())
        print(valid_signature)

        # Build new ICA cert (ICA2) with a new private key
        ica2_private_key = self.create_private_key()
        _ica2 = self.create_ica_cert(rca_private_key,
                                     ica2_private_key,
                                     outpath="ica2.pem")

        # Build new SICA cert (SICA2) without the OCSP signing EKU, but with the same private key as ICA
        sica2 = self.create_sica_cert(ica2_private_key,
                                      sica_private_key,
                                      outpath="sica2.pem",
                                      ocsp_signing_eku=False)

        # Revoke ICA and build CRL
        rca_crl = self.build_crl([ica], rca, rca_private_key, outpath="rca.crl")

        # Revoke SICA and build CRL, sign CRL using new private key (the one of ICA2)
        ica2_crl = self.build_crl([sica], ica, ica2_private_key, outpath="ica2.crl")

        # Do the same as above but sign the CRL using the old private key (the one of ICA) for testing purposes
        ica_crl = self.build_crl([sica], ica, ica_private_key, outpath="ica.crl")

        # Build an empty CRL and sign it with SICA2's private key (which is the same as SICA's)
        sica2_crl = self.build_crl([], sica2, sica_private_key, outpath="sica2.crl")

        # Verify CRL signatures
        print("Verify CRL signatures ...")
        valid_signature = self.verify_crl_signature(rca_crl, rca_private_key.public_key())
        print(valid_signature)
        valid_signature = self.verify_crl_signature(ica_crl, ica_private_key.public_key())
        print(valid_signature)
        valid_signature = self.verify_crl_signature(ica2_crl, ica2_private_key.public_key())
        print(valid_signature)
        valid_signature = self.verify_crl_signature(sica2_crl, sica_private_key.public_key())
        print(valid_signature)

    def verify_certificate_signature(self, cert, public_key,
                                     pad=padding.PKCS1v15()):
        valid_signature = True
        try:
            public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                pad,
                cert.signature_hash_algorithm)
        except InvalidSignature:
            valid_signature = False
        return valid_signature

    def verify_crl_signature(self, crl, public_key,
                             pad=padding.PKCS1v15()):
        valid_signature = True
        try:
            public_key.verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                pad,
                crl.signature_hash_algorithm)
        except InvalidSignature:
            valid_signature = False
        return valid_signature

    def build_crl(self, certs_to_revoke, issuer_cert, issuer_private_key, outpath=None):
        crlb = x509.CertificateRevocationListBuilder()

        for cert in certs_to_revoke:
            rcb = x509.RevokedCertificateBuilder()
            rcb = rcb.revocation_date(datetime.datetime.utcnow())
            rcb = rcb.serial_number(cert.serial_number)
            revoked_cert = rcb.build(default_backend())
            crlb = crlb.add_revoked_certificate(revoked_cert)

        crlb = crlb.issuer_name(issuer_cert.subject)
        crlb = crlb.last_update(datetime.datetime.utcnow())
        crlb = crlb.next_update(datetime.datetime.utcnow() + datetime.timedelta(days=60))
        crl = crlb.sign(issuer_private_key, algorithm=hashes.SHA256())

        self.save_to_pem(crl, outpath)

        return crl

    def create_cert(self, not_before, not_after, serial_number, issuer_private_key, private_key,
                    subject_entries=[],
                    issuer_entries=[],
                    extensions=[]):
        cb = x509.CertificateBuilder()

        # subject
        subject = []
        for oid, value in subject_entries:
            subject.append(x509.NameAttribute(oid, value))
        cb = cb.subject_name(x509.Name(subject))

        # issuer
        issuer = []
        for oid, value in issuer_entries:
            issuer.append(x509.NameAttribute(oid, value))
        cb = cb.issuer_name(x509.Name(issuer))

        cb = cb.not_valid_before(not_before)
        cb = cb.not_valid_after(not_after)
        cb = cb.serial_number(serial_number)
        cb = cb.public_key(private_key.public_key())

        for extension, critical in extensions:
            cb = cb.add_extension(extension, critical=critical)

        certificate = cb.sign(issuer_private_key, hashes.SHA256(), default_backend())
        return certificate

    def create_private_key(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        return private_key

    def create_rca_cert(self, issuer_private_key, outpath=None):
        subject_entries = [
            (NameOID.COUNTRY_NAME, "US"),
            (NameOID.ORGANIZATION_NAME, "Root CA"),
            (NameOID.COMMON_NAME, "Root CA Name"),
        ]
        issuer_entries = [
            (NameOID.COUNTRY_NAME, "US"),
            (NameOID.ORGANIZATION_NAME, "Root CA"),
            (NameOID.COMMON_NAME, "Root CA Name"),
        ]

        not_before = datetime.datetime.fromisoformat("2011-01-01 11:11:11")
        not_after = datetime.datetime.fromisoformat("2041-01-01 11:11:11")
        serial_number = x509.random_serial_number()

        # basic constraints
        basic_constraints_ca = True
        basic_constraints_pathlen = None

        # key usage:  Certificate Sign and CRL Sign set to True, rest set to False
        key_usages = 5 * [False] + 2 * [True] + 2 * [False]

        extensions = [
            (x509.BasicConstraints(basic_constraints_ca, basic_constraints_pathlen), True),
            (x509.KeyUsage(*key_usages), True),
            (x509.SubjectKeyIdentifier.from_public_key(issuer_private_key.public_key()), False),
        ]

        cert = self.create_cert(
            not_before,
            not_after,
            serial_number,
            issuer_private_key,  # self-signed
            issuer_private_key,
            subject_entries=subject_entries,
            issuer_entries=issuer_entries,
            extensions=extensions
        )

        self.save_to_pem(cert, outpath)

        return cert

    def create_ica_cert(self, issuer_private_key, private_key, outpath=None):
        subject_entries = [
            (NameOID.COUNTRY_NAME, "US"),
            (NameOID.ORGANIZATION_NAME, "Intermediate CA"),
            (NameOID.COMMON_NAME, "Intermediate CA Name"),
        ]
        issuer_entries = [
            (NameOID.COUNTRY_NAME, "US"),
            (NameOID.ORGANIZATION_NAME, "Root CA"),
            (NameOID.COMMON_NAME, "Root CA Name"),
        ]

        not_before = datetime.datetime.fromisoformat("2016-01-01 11:11:11")
        not_after = datetime.datetime.fromisoformat("2031-01-01 11:11:11")
        serial_number = x509.random_serial_number()

        aia_descriptions = [
            x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.OCSP,
                                   x509.UniformResourceIdentifier("http://ocsp.rootca.com")),
            x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                                   x509.UniformResourceIdentifier("http://sub.rootca.com/rca.crt")),
        ]

        # basic constraints
        basic_constraints_ca = True
        basic_constraints_pathlen = None

        certificate_policies = [
            x509.PolicyInformation(x509.oid.CertificatePoliciesOID.ANY_POLICY,
                                   ["http://www.rootca.com/repo"]),
        ]

        crl_distribution_points = [
            x509.DistributionPoint([x509.UniformResourceIdentifier("http://crl.rootca.com/rca.crl")],
                                   None, None, None)
        ]

        # key usage:  Certificate Sign and CRL Sign set to True, rest set to False
        key_usages = 5 * [False] + 2 * [True] + 2 * [False]

        extensions = [
            (x509.BasicConstraints(basic_constraints_ca, basic_constraints_pathlen), True),
            (x509.CertificatePolicies(policies=certificate_policies), False),
            (x509.AuthorityInformationAccess(descriptions=aia_descriptions), False),
            (x509.KeyUsage(*key_usages), True),
            (x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_private_key.public_key()), False),
            (x509.CRLDistributionPoints(crl_distribution_points), False),
            (x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), False),
        ]

        cert = self.create_cert(
            not_before,
            not_after,
            serial_number,
            issuer_private_key,
            private_key,
            subject_entries=subject_entries,
            issuer_entries=issuer_entries,
            extensions=extensions
        )

        self.save_to_pem(cert, outpath)

        return cert

    def create_sica_cert(self, issuer_private_key, private_key, outpath=None,
                         ocsp_signing_eku=True):
        subject_entries = [
            (NameOID.COUNTRY_NAME, "US"),
            (NameOID.ORGANIZATION_NAME, "My Company"),
            (NameOID.COMMON_NAME, "My Company Name"),
        ]
        issuer_entries = [
            (NameOID.COUNTRY_NAME, "US"),
            (NameOID.ORGANIZATION_NAME, "Intermediate CA"),
            (NameOID.COMMON_NAME, "Intermediate CA Name"),
        ]

        not_before = datetime.datetime.fromisoformat("2016-02-02 10:10:10")
        not_after = datetime.datetime.fromisoformat("2022-02-02 10:10:10")
        serial_number = x509.random_serial_number()

        aia_descriptions = [
            x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                                   x509.UniformResourceIdentifier("http://sub.rootca.com/ica.crt")),
            x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.OCSP,
                                   x509.UniformResourceIdentifier("http://ica.ocsp.rootca.com")),
        ]
        eku_usages = [
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
            x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"),  # smartcardLogon (Microsoft enhanced key usage)
        ]
        if ocsp_signing_eku:
            eku_usages.append(x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING)

        # basic constraints
        basic_constraints_ca = True
        basic_constraints_pathlen = 0

        certificate_policies = [
            x509.PolicyInformation(x509.oid.CertificatePoliciesOID.CPS_QUALIFIER,
                                   ["http://www.rootca.com/repo"]),
            x509.PolicyInformation(x509.oid.CertificatePoliciesOID.CPS_QUALIFIER, ["http://www.mycompany.com/cp/"]),
        ]

        crl_distribution_points = [
            x509.DistributionPoint([x509.UniformResourceIdentifier("http://crl.rootca.com/ica.crl")],
                                   None, None, None)
        ]

        # key usage:  Certificate Sign and CRL Sign set to True, rest set to False
        key_usages = 5 * [False] + 2 * [True] + 2 * [False]

        extensions = [
            (x509.AuthorityInformationAccess(descriptions=aia_descriptions), False),
            (x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), False),
            (x509.BasicConstraints(basic_constraints_ca, basic_constraints_pathlen), True),
            (x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_private_key.public_key()), False),
            (x509.CertificatePolicies(policies=certificate_policies), False),
            (x509.CRLDistributionPoints(crl_distribution_points), False),
            (x509.KeyUsage(*key_usages), True),
            (x509.ExtendedKeyUsage(usages=eku_usages), False),
        ]

        cert = self.create_cert(
            not_before,
            not_after,
            serial_number,
            issuer_private_key,  # use issuer private key to sign => do not self sign
            private_key,
            subject_entries=subject_entries,
            issuer_entries=issuer_entries,
            extensions=extensions
        )

        self.save_to_pem(cert, outpath)

        return cert

    def create_ee_cert(self, issuer_private_key, private_key, outpath=None):
        subject_entries = [
            (NameOID.COUNTRY_NAME, "US"),
            (NameOID.ORGANIZATION_NAME, "My Company"),
            (NameOID.COMMON_NAME, "firstname.lastname@mycompany.com"),
        ]
        issuer_entries = [
            (NameOID.COUNTRY_NAME, "US"),
            (NameOID.ORGANIZATION_NAME, "My Company"),
            (NameOID.COMMON_NAME, "My Company Name"),
        ]

        not_before = datetime.datetime.fromisoformat("2016-08-08 15:15:15")
        not_after = datetime.datetime.fromisoformat("2025-08-08 15:15:15")
        serial_number = x509.random_serial_number()

        aia_descriptions = [
            x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
                                   x509.UniformResourceIdentifier("http://sub.mycompany.com/sica.crt")),
        ]
        eku_usages = [
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
            x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.2"),  # smartcardLogon (Microsoft enhanced key usage)
        ]
        # basic constraints
        basic_constraints_ca = False
        basic_constraints_pathlen = None

        certificate_policies = [
            x509.PolicyInformation(x509.oid.CertificatePoliciesOID.CPS_QUALIFIER, ["http://www.mycompany.com/cp/"]),
        ]

        # key usage:  Signing only
        key_usages = [True] + 8 * [False]

        # subject alternative names
        subject_alternative_names = [
            x509.DNSName("firstname.lastname@mycompany.com"),
        ]

        crl_distribution_points = [
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier("http://crl.mycompany.com/sica.crl")],
                None, None, None)
        ]

        extensions = [
            (x509.AuthorityInformationAccess(descriptions=aia_descriptions), False),
            (x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), False),
            (x509.BasicConstraints(basic_constraints_ca, basic_constraints_pathlen), True),
            (x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_private_key.public_key()), False),
            (x509.CertificatePolicies(policies=certificate_policies), False),
            (x509.CRLDistributionPoints(crl_distribution_points), False),
            (x509.KeyUsage(*key_usages), True),
            (x509.ExtendedKeyUsage(usages=eku_usages), False),
            (x509.SubjectAlternativeName(subject_alternative_names), False),
        ]

        cert = self.create_cert(
            not_before,
            not_after,
            serial_number,
            issuer_private_key,  # use issuer private key to sign => do not self sign
            private_key,
            subject_entries=subject_entries,
            issuer_entries=issuer_entries,
            extensions=extensions
        )

        self.save_to_pem(cert, outpath)

        return cert

    def save_to_pem(self, cert_or_crl, outpath, encoding=Encoding.PEM):
        if outpath is not None:
            pem_bytes = cert_or_crl.public_bytes(encoding)
            print(f"Saving to file {outpath} ...")
            with open(outpath, "wb+") as fout:
                fout.write(pem_bytes)


def main():
    builder = CAHierarchyBuilder()
    builder.build()


if __name__ == "__main__":
    main()
