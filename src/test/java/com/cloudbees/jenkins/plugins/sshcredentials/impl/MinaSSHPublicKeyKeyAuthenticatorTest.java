package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticator;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.CredentialsDescriptor;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.util.Secret;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class MinaSSHPublicKeyKeyAuthenticatorTest {

    private final String username = "foomanchu";

    private SshServer sshd;

    @Rule
    public JenkinsRule r = new JenkinsRule();

    private final SSHUserPrivateKey user = new SSHUserPrivateKey() {

        @NonNull
        public String getUsername() {
            return username;
        }

        @NonNull
        public String getDescription() {
            return "";
        }

        @NonNull
        public String getId() {
            return "";
        }

        public CredentialsScope getScope() {
            return CredentialsScope.SYSTEM;
        }

        @NonNull
        public CredentialsDescriptor getDescriptor() {
            return new CredentialsDescriptor() {
                @Override
                @NonNull
                public String getDisplayName() {
                    return "";
                }
            };
        }

        @NonNull
        public String getPrivateKey() {
            // just want a valid key... I generated this and have thrown it away (other than here)
            // do not use other than in this test
            return "-----BEGIN RSA PRIVATE KEY-----\n"
                + "MIICWQIBAAKBgQDADDwooNPJNQB4N4bJPiBgq/rkWKMABApX0w4trSkkX5q+l+CL\n"
                + "CuddGGAsAu6XPari8v49ipbBmHqRLP9+X3ARGWKU2gDvGTBr99/ReUl2YgVjCwy+\n"
                + "KMrGCN7SNTgRo6StwVaPhh6pUpNTQciDe/kOwUnQFWSM6/lwkOD1Uod45wIBIwKB\n"
                + "gHi3O8HELVnmzRhdaqphkLHLL/0/B18Ye4epPBy1/JqFPLJQ1kjFBnUIAe/HVCSN\n"
                + "KZX30wIcmUZ9GdeYoJiTwsfTy9t2KwHjqrapTfiekVZAW+3iDBqRZMxQ5MoK7b6g\n"
                + "w5HrrtrtPfYuAsBnYjIS6qsKAVT3vdolJ5eai/RlPO4LAkEA76YuUozC/dW7Ox+R\n"
                + "1Njd6cWJsRVXGemkSYY/rSh0SbfHAebqL/bDg8xXim9UiuD9Hc6md3glHQj6iKvl\n"
                + "BxWq4QJBAM0moKiM16WFSFJP1wVDj0Bnx6DkJYSpf5u+C0ghBVoqIYKq6/P/gRE2\n"
                + "+ColsLu6AYftaEJVpAgxeTU/IsGoJMcCQHRmqMkCipiMYkFJ2R49cxnGWNJa0ojt\n"
                + "03QrQ3/9tNNZQ2dS5sbW8UAEKoURgNW9vMVVvpHMpE/uaw8u65W6ESsCQDTAyjn4\n"
                + "VLWIrDJsTTveLCaBFhNt3cMHA45ysnGiF1GzD+5mdzAdITBP9qvAjIgLQjjlRrH4\n"
                + "w8eXsXQXjJgyjR0CQHfvhiMPG5pWwmXpsEOFo6GKSvOC/5sNEcnddenuO/2T7WWi\n"
                + "o1LQh9naeuX8gti0vNR8+KtMEaIcJJeWnk56AVY=\n"
                + "-----END RSA PRIVATE KEY-----\n";
        }

        @CheckForNull
        public Secret getPassphrase() {
            return null;
        }

        @NonNull
        public List<String> getPrivateKeys() {
            return Collections.singletonList(getPrivateKey());
        }
    };

    @After
    public void tearDown() {
        if (sshd != null) {
            try {
                sshd.stop(true);
            } catch (IOException e) {
                Logger.getLogger(getClass().getName()).log(Level.WARNING, "Problems shutting down ssh server", e);
            }
        }
    }

    @Before
    public void setUp() throws IOException {
        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(0);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
        sshd.setPublickeyAuthenticator((s, publicKey, serverSession) -> username.equals(s));
        sshd.setUserAuthFactories(Collections.singletonList(new UserAuthPublicKeyFactory()));
        try {
            sshd.start();
            Logger.getLogger(getClass().getName()).log(Level.INFO, "Started ssh Server");
        } catch (Throwable e) {
            Logger.getLogger(getClass().getName()).log(Level.WARNING, "Problems starting ssh server", e);
            try {
                sshd.stop();
            } catch (Throwable t) {
                Logger.getLogger(getClass().getName()).log(Level.WARNING, "Problems shutting down ssh server", t);
            }
            throw e;
        }
    }

    @Test
    public void testAuthenticate() throws Exception {
        try (SshClient sshClient = SshClient.setUpDefaultClient()) {
            sshClient.start();
            try (ClientSession connection = sshClient
                .connect(username, "localhost", sshd.getPort())
                .verify(15, TimeUnit.SECONDS)
                .getSession()) {

                MinaSSHPublicKeyAuthenticator instance = new MinaSSHPublicKeyAuthenticator(connection, user);
                assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
                assertThat(instance.canAuthenticate(), is(true));
                assertThat(instance.authenticate(), is(true));
                assertThat(instance.isAuthenticated(), is(true));
            }
        }

//        MinaConnector connector = new MinaConnector(username, "localhost", sshd.getPort());
//        try {
//            MinaSSHPublicKeyAuthenticator instance = new MinaSSHPublicKeyAuthenticator(connector.getSession(), user);
//            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
//            assertThat(instance.canAuthenticate(), is(true));
//            assertThat(instance.authenticate(), is(true));
//            assertThat(instance.isAuthenticated(), is(true));
//
//        } finally {
//            connector.close();
//        }
    }

    @Test
    public void testFactory() throws Exception {
        try (SshClient sshClient = SshClient.setUpDefaultClient()) {
            sshClient.start();
            try (ClientSession connection = sshClient
                .connect(username, "localhost", sshd.getPort())
                .verify(15, TimeUnit.SECONDS)
                .getSession()) {

                SSHAuthenticator<Object, StandardUsernameCredentials> instance = SSHAuthenticator.newInstance(connection, user);
                assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
                assertThat(instance.canAuthenticate(), is(true));
                assertThat(instance.authenticate(), is(true));
                assertThat(instance.isAuthenticated(), is(true));
            }
        }
//        MinaConnector connector = new MinaConnector(username, "localhost", sshd.getPort());
//        try {
//            SSHAuthenticator<Object, StandardUsernameCredentials> instance = SSHAuthenticator.newInstance(connector.getSession(), user);
//            assertThat(instance.getAuthenticationMode(), is(SSHAuthenticator.Mode.AFTER_CONNECT));
//            assertThat(instance.canAuthenticate(), is(true));
//            assertThat(instance.authenticate(), is(true));
//            assertThat(instance.isAuthenticated(), is(true));
//        } finally {
//            connector.close();
//        }
    }
}
