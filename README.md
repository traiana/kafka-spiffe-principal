## Kafka SPIFFE Principal Builder

A custom `KafkaPrincipalBuilder` implementation for Apache Kafka.
This class and documentation deals only with `SslAuthenticationContext`, we do not support any other context at the moment (Kerberos, SASL, Oauth)

#### Default behavior
The default `DefaultKafkaPrincipalBuilder` class that comes with Apache Kafka builds a principal
name according to the x509 Subject in the SSL certificate. Since there is no logic that deals with *Subject Alternative Name*,
this approach cannot handle a *SPIFFE ID*.

#### New behavior
The principal builder first looks for any valid *SPIFFE ID* in the certificate, if found, the *KafkaPrincipal* that will
be returned would be seen by an *ACL Authorizer* as **SPIFFE:spiffe://some.spiffe.id.uri**. If that fails, a normal usage of the Subject will
used with a normal **USER:CN=...**
   