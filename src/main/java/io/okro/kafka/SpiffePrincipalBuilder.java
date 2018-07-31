package io.okro.kafka;

import org.apache.kafka.common.security.auth.AuthenticationContext;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.KafkaPrincipalBuilder;
import org.apache.kafka.common.security.auth.SslAuthenticationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

public class SpiffePrincipalBuilder implements KafkaPrincipalBuilder {
    private static final Logger LOG = LoggerFactory.getLogger(SpiffePrincipalBuilder.class);

    private static final String SPIFFE_TYPE = "SPIFFE";

    public KafkaPrincipal build(AuthenticationContext context) {
        if (!(context instanceof SslAuthenticationContext)) {
            LOG.trace("non-SSL connection coerced to ANONYMOUS");
            return KafkaPrincipal.ANONYMOUS;
        }

        SSLSession session = ((SslAuthenticationContext) context).session();
        X509Certificate cert = firstX509(session);
        if (cert == null) {
            LOG.trace("first peer certificate missing / not x509");
            return KafkaPrincipal.ANONYMOUS;
        }

        String spiffeId = spiffeId(cert);
        if (spiffeId == null) {
            return new KafkaPrincipal(KafkaPrincipal.USER_TYPE, cert.getSubjectX500Principal().getName());
        }

        return new KafkaPrincipal(SPIFFE_TYPE, spiffeId);
    }

    private @Nullable X509Certificate firstX509(SSLSession session) {
        try {
            Certificate[] peerCerts = session.getPeerCertificates();
            if (peerCerts.length == 0) {
                return null;
            }
            Certificate first = peerCerts[0];
            if (!(first instanceof X509Certificate)) {
                return null;
            }
            return (X509Certificate) first;
        } catch (SSLPeerUnverifiedException e) {
            LOG.warn("failed to extract certificate", e);
            return null;
        }
    }

    private @Nullable String spiffeId(X509Certificate cert) {
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans == null) {
                return null;
            }

            return sans.stream()
                    .map(san -> (String) san.get(1))
                    .filter(uri -> uri.startsWith("spiffe://"))
                    .findFirst()
                    .orElse(null);
        } catch (CertificateParsingException e) {
            LOG.warn("failed to parse SAN", e);
            return null;
        }
    }
}