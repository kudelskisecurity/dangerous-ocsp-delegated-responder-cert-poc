#!/usr/bin/env bash

echo ">>> Running main.py ..."
python main.py

echo
echo ">>> Testing new chain locally ..."
openssl verify -verbose -x509_strict -show_chain \
-crl_check_all -CRLfile rca.crl -CRLfile ica2.crl -CRLfile sica2.crl \
-trusted rca.pem \
-untrusted ica2.pem \
-untrusted sica2.pem \
ee.pem

echo
echo ">>> Testing old chain locally (should fail with invalid CRL signature) ..."
openssl verify -verbose -x509_strict -show_chain \
-crl_check_all -CRLfile rca.crl -CRLfile ica2.crl -CRLfile sica2.crl \
-trusted rca.pem \
-untrusted ica.pem \
-untrusted sica.pem \
ee.pem

echo
echo ">>> Testing old chain locally but with CRL signed by old key (should fail and say certificate revoked) ..."
openssl verify -verbose -x509_strict -show_chain \
-crl_check_all -CRLfile rca.crl -CRLfile ica.crl -CRLfile sica2.crl \
-trusted rca.pem \
-untrusted ica.pem \
-untrusted sica.pem \
ee.pem