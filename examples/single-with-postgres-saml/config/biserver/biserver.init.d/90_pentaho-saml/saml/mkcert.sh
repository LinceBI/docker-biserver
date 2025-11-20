#!/bin/sh

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "${0:?}")" && pwd -P)

KEYSTORE_FILE="${SCRIPT_DIR:?}"/keystore.jks
SP_METADATA_FILE="${SCRIPT_DIR:?}"/sp-metadata.xml

if [ ! -f "${KEYSTORE_FILE:?}" ]; then
	keytool -genkey -alias saml -dname 'CN=saml' -keyalg RSA -sigalg SHA256withRSA -keysize 2048 -validity 7300 -keypass changeit -storepass changeit -keystore "${KEYSTORE_FILE:?}"
	keytool -list -storepass changeit -keystore "${KEYSTORE_FILE:?}"
fi

PENTAHO_FQDN="https://example.localhost/pentaho"
CERTIFICATE=$(keytool -list -rfc -alias saml -storepass changeit -keystore "${KEYSTORE_FILE:?}" | openssl x509 -inform pem -outform der | base64 -w0)

cat > "${SP_METADATA_FILE:?}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="biserver" entityID="biserver">
	<md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="false">
		<md:KeyDescriptor use="signing">
			<ds:KeyInfo>
				<ds:X509Data>
					<ds:X509Certificate>${CERTIFICATE:?}</ds:X509Certificate>
				</ds:X509Data>
			</ds:KeyInfo>
		</md:KeyDescriptor>
		<md:KeyDescriptor use="encryption">
			<ds:KeyInfo>
				<ds:X509Data>
					<ds:X509Certificate>${CERTIFICATE:?}</ds:X509Certificate>
				</ds:X509Data>
			</ds:KeyInfo>
		</md:KeyDescriptor>
		<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${PENTAHO_FQDN:?}/saml/SingleLogout" />
		<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${PENTAHO_FQDN:?}/saml/SingleLogout" />
		<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
		<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
		<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
		<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
		<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</md:NameIDFormat>
		<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="${PENTAHO_FQDN:?}/saml/SSO" index="0" isDefault="true" />
		<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="${PENTAHO_FQDN:?}/saml/SSO" index="1" />
	</md:SPSSODescriptor>
</md:EntityDescriptor>
EOF
