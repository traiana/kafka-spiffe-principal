package io.okro.kafka;

import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.PlaintextAuthenticationContext;
import org.apache.kafka.common.security.auth.SecurityProtocol;
import org.apache.kafka.common.security.auth.SslAuthenticationContext;
import org.junit.Test;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SpiffePrincipalBuilderTest {

    private SslAuthenticationContext mockedSslContext(String certPath) throws CertificateException, SSLPeerUnverifiedException, UnknownHostException {
        // load cert
        ClassLoader classLoader = getClass().getClassLoader();
        InputStream in = classLoader.getResourceAsStream(certPath);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(in);

        // mock ssl session
        SSLSession session = mock(SSLSession.class);
        when(session.getPeerCertificates()).thenReturn(new Certificate[]{cert});
        return new SslAuthenticationContext(session, InetAddress.getLocalHost(), SecurityProtocol.SSL.name());
    }

    /**
     * X509 V3 with a SPIFFE-based SAN extension.
     * Should result in 'SPIFFE:[spiffe://uri]'
     */
    @Test
    public void TestSpiffeCert() throws CertificateException, SSLPeerUnverifiedException, UnknownHostException {
        SslAuthenticationContext context = mockedSslContext("spiffe-cert.pem");
        KafkaPrincipal principal = new SpiffePrincipalBuilder().build(context);

        assertEquals("SPIFFE", principal.getPrincipalType());
        assertEquals(principal.getName(), "spiffe://srv1.okro.io");
    }

    /**
     * X509 V1 certificate with no SAN extension.
     * Should fall back to 'User:CN=[CN]'
     */
    @Test
    public void TestSubjectOnlyCert() throws CertificateException, SSLPeerUnverifiedException, UnknownHostException {
        SslAuthenticationContext context = mockedSslContext("subject-only-cert.pem");
        KafkaPrincipal principal = new SpiffePrincipalBuilder().build(context);

        assertEquals(KafkaPrincipal.USER_TYPE, principal.getPrincipalType());
        assertEquals(principal.getName(), "CN=srv2,OU=architects,O=okro.io,L=Tel-Aviv,ST=Tel-Aviv,C=IL");
    }

    /**
     * X509 V3 with a non-SPIFFE SAN extension.
     * Should fall back to 'User:CN=[CN]'
     */
    @Test
    public void TestSanNoSpiffeCert() throws CertificateException, SSLPeerUnverifiedException, UnknownHostException {
        SslAuthenticationContext context = mockedSslContext("san-no-spiffe-cert.pem");
        KafkaPrincipal principal = new SpiffePrincipalBuilder().build(context);

        assertEquals(KafkaPrincipal.USER_TYPE, principal.getPrincipalType());
        assertEquals(principal.getName(), "CN=srv3,OU=architects,O=okro.io,L=Tel-Aviv,ST=Tel-Aviv,C=IL");
    }

    /**
     * Non-SSL context.
     * Should be unauthenticated.
     */
    @Test
    public void TestNoSSLContext() throws java.net.UnknownHostException {
        PlaintextAuthenticationContext context = new PlaintextAuthenticationContext(InetAddress.getLocalHost(), SecurityProtocol.SSL.name());
        KafkaPrincipal principal = new SpiffePrincipalBuilder().build(context);

        assertEquals(KafkaPrincipal.ANONYMOUS, principal);
    }
}
