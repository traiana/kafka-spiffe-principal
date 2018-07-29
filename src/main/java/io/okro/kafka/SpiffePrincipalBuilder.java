package io.okro.kafka;

import org.apache.kafka.common.security.auth.*;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import static org.apache.commons.lang3.StringUtils.startsWith;

public class SpiffePrincipalBuilder implements KafkaPrincipalBuilder {
    public KafkaPrincipal build(AuthenticationContext context) {
        if (context instanceof PlaintextAuthenticationContext) {
            return KafkaPrincipal.ANONYMOUS;
        }

        if (!(context instanceof SslAuthenticationContext)) {
            throw new IllegalArgumentException("Unhandled authentication context type: " + context.getClass().getName());
        }

        SSLSession sslSession = ((SslAuthenticationContext) context).session();
        try {
            Certificate[] peerCerts = sslSession.getPeerCertificates();
            if (peerCerts == null || peerCerts.length == 0) {
                return KafkaPrincipal.ANONYMOUS;
            }
            if (!(peerCerts[0] instanceof X509Certificate)) {
                return KafkaPrincipal.ANONYMOUS;
            }
            X509Certificate cert = (X509Certificate) peerCerts[0];
            return cert.getSubjectAlternativeNames().stream()
                    .map(san -> (String) san.get(1))
                    .filter(uri -> startsWith(uri, "spiffe://"))
                    .findFirst()
                    .map(s -> new KafkaPrincipal(KafkaPrincipal.USER_TYPE, s))
                    .orElse(KafkaPrincipal.ANONYMOUS);
        } catch (SSLPeerUnverifiedException | CertificateParsingException se) {
            return KafkaPrincipal.ANONYMOUS;
        }
    }
}
