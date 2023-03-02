package io.okro.kafka;

import org.apache.kafka.common.errors.SerializationException;
import org.apache.kafka.common.message.DefaultPrincipalData;
import org.apache.kafka.common.protocol.ByteBufferAccessor;
import org.apache.kafka.common.protocol.MessageUtil;
import org.apache.kafka.common.security.auth.AuthenticationContext;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.KafkaPrincipalBuilder;
import org.apache.kafka.common.security.auth.KafkaPrincipalSerde;
import org.apache.kafka.common.security.auth.SslAuthenticationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.nio.ByteBuffer;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

public class SpiffePrincipalBuilder implements KafkaPrincipalBuilder, KafkaPrincipalSerde {
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

    @Override
    public byte[] serialize(KafkaPrincipal principal) throws SerializationException {
        DefaultPrincipalData data = new DefaultPrincipalData()
                .setType(principal.getPrincipalType())
                .setName(principal.getName())
                .setTokenAuthenticated(principal.tokenAuthenticated());
        return MessageUtil.toVersionPrefixedBytes(DefaultPrincipalData.HIGHEST_SUPPORTED_VERSION, data);
    }

    @Override
    public KafkaPrincipal deserialize(byte[] bytes) throws SerializationException {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        short version = buffer.getShort();
        if (version < DefaultPrincipalData.LOWEST_SUPPORTED_VERSION || version > DefaultPrincipalData.HIGHEST_SUPPORTED_VERSION) {
            throw new SerializationException("Invalid principal data version " + version);
        }

        DefaultPrincipalData data = new DefaultPrincipalData(new ByteBufferAccessor(buffer), version);
        return new KafkaPrincipal(data.type(), data.name(), data.tokenAuthenticated());
    }
}
