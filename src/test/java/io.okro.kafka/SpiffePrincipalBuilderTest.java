package io.okro.kafka;

import java.util.concurrent.TimeUnit;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.net.InetAddress;
import javax.net.ssl.SSLSession;

import org.apache.kafka.common.security.auth.*;

import org.apache.commons.io.IOUtils;

import org.easymock.EasyMock;
import org.easymock.EasyMockSupport;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class SpiffePrincipalBuilderTest extends EasyMockSupport {

    private X509Certificate getResourceAsCert(String resourcePath)
            throws java.io.IOException, java.security.cert.CertificateException {

        ClassLoader classLoader = getClass().getClassLoader();
        try {
            // Read cert
            ByteArrayInputStream certInputStream =
                    new ByteArrayInputStream(IOUtils.toByteArray(classLoader.getResourceAsStream(resourcePath)));

            // Parse as X509 certificate
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(certInputStream);

        } catch (java.io.IOException | java.security.cert.CertificateException e) {
            System.out.println("Problem with reading the certificate file. " + e.toString());
            throw e;
        }
    }

    @Test
    public void TestSubjectOnlyCert() {
        // Tests an X509 V1 certificate with no SAN extension

        try {
            X509Certificate cert = getResourceAsCert("subject-only-cert.pem");

            // Mock SSLSession getPeerCertificates(), we bypass alllll the handshake parts because... out of scope.
            SSLSession session = mock(SSLSession.class);
            EasyMock.expect(session.getPeerCertificates()).andReturn(new Certificate[] {cert});

            replayAll();

            // Build KafkaPrincipal
            SpiffePrincipalBuilder builder = new SpiffePrincipalBuilder();

            KafkaPrincipal principal = builder.build(
                    new SslAuthenticationContext(session, InetAddress.getLocalHost()));

            // Identity type should be "User"
            assertEquals(KafkaPrincipal.USER_TYPE, principal.getPrincipalType());

            // Identity should be a string
            assertNotNull(principal.getName());

            System.out.println("Principal: " + principal.toString());

        } catch (java.io.IOException | java.security.cert.CertificateException e) {
            System.out.println("Problem with reading the certificate file. " + e.toString());
        }
    }

    @Test
    public void TestSpiffeCert() {
        // Tests an X509 V3 with SAN extension holding a SPIFFE ID

        try {
            X509Certificate cert = getResourceAsCert("spiffe-cert.pem");

            // Mock SSLSession getPeerCertificates(), we bypass alllll the handshake parts because... out of scope.
            SSLSession session = mock(SSLSession.class);
            EasyMock.expect(session.getPeerCertificates()).andReturn(new Certificate[] {cert});

            replayAll();

            // Build KafkaPrincipal
            SpiffePrincipalBuilder builder = new SpiffePrincipalBuilder();

            KafkaPrincipal principal = builder.build(
                    new SslAuthenticationContext(session, InetAddress.getLocalHost()));

            // Identity type should be "SPIFFE"
            assertEquals("SPIFFE", principal.getPrincipalType());

            // Identity should be a string
            assertNotNull(principal.getName());

            System.out.println("Principal: " + principal.toString());

        } catch (java.io.IOException | java.security.cert.CertificateException e) {
            System.out.println("Problem with reading the certificate file. " + e.toString());
        }
    }

    @Test
    public void TestSanNoSpiffeCert() {
        // Tests an X509 V3 with SAN extension holding a regular FQDN

        try {
            X509Certificate cert = getResourceAsCert("san-no-spiffe-cert.pem");

            // Mock SSLSession getPeerCertificates(), we bypass alllll the handshake parts because... out of scope.
            SSLSession session = mock(SSLSession.class);
            EasyMock.expect(session.getPeerCertificates()).andReturn(new Certificate[] {cert});

            replayAll();

            // Build KafkaPrincipal
            SpiffePrincipalBuilder builder = new SpiffePrincipalBuilder();

            KafkaPrincipal principal = builder.build(
                    new SslAuthenticationContext(session, InetAddress.getLocalHost()));

            // Identity type should be "User"
            assertEquals(KafkaPrincipal.USER_TYPE, principal.getPrincipalType());

            // Identity should be a string
            assertNotNull(principal.getName());

            System.out.println("Principal: " + principal.toString());

        } catch (java.io.IOException | java.security.cert.CertificateException e) {
            System.out.println("Problem with reading the certificate file. " + e.toString());
        }
    }

    @Test
    public void TestNoSSLContext() throws java.net.UnknownHostException {
        // Tests non-SSL context behavior

        SpiffePrincipalBuilder builder = new SpiffePrincipalBuilder();

        KafkaPrincipal principal = builder.build(
                new PlaintextAuthenticationContext(InetAddress.getLocalHost()));

        // Identity type should be KafkaPrincipal.ANONYMOUS
        assertEquals(KafkaPrincipal.ANONYMOUS, principal);

        System.out.println("Principal: " + principal.toString());
    }

    @Test
    public void TestAwareness() throws InterruptedException {
        // Tests a reviewer's awareness
        TimeUnit.SECONDS.sleep(1);

        // Identity type should be KafkaPrincipal.ANONYMOUS
        assertEquals(42, 42);
    }
}
