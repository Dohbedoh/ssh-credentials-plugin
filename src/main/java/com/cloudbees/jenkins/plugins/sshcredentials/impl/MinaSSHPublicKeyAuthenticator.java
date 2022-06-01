/*
 * The MIT License
 *
 * Copyright (c) 2011-2012, CloudBees, Inc., Stephen Connolly.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticator;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticatorFactory;
import com.cloudbees.jenkins.plugins.sshcredentials.SSHUserPrivateKey;
import com.cloudbees.plugins.credentials.common.StandardUsernameCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.Extension;
import hudson.util.Secret;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceLoader;
import org.apache.sshd.common.util.io.resource.AbstractIoResource;
import org.apache.sshd.common.util.security.SecurityUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Does public key auth with a {@link ClientSession}.
 * Note: The credentials' username must be retrieved by the caller and passed to the client that creates the
 * {@link ClientSession}., for example using {@link org.apache.sshd.client.SshClient#connect}.
 */
public class MinaSSHPublicKeyAuthenticator extends SSHAuthenticator<ClientSession, SSHUserPrivateKey> {

    /**
     * Our logger.
     */
    private static final Logger LOGGER = Logger.getLogger(MinaSSHPublicKeyAuthenticator.class.getName());


    /**
     * Constructor.
     *
     * @param connection the connection we will be authenticating.
     */
    public MinaSSHPublicKeyAuthenticator(@NonNull ClientSession connection,
                                         @NonNull SSHUserPrivateKey user) {
        super(connection, user, null);
    }

    /**
     * Constructor.
     *
     * @param connection the connection we will be authenticating.
     */
    public MinaSSHPublicKeyAuthenticator(@NonNull ClientSession connection,
                                         @NonNull SSHUserPrivateKey user,
                                         @CheckForNull String username) {
        super(connection, user, username);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean canAuthenticate() {
//        return getConnection().getUserAuthFactories().stream().anyMatch(userAuthFactory -> userAuthFactory instanceof UserAuthPublicKeyFactory)
//            && !getConnection().isAuthenticated() && !getConnection().isOpen();
        //TODO
        return super.canAuthenticate();
    }

    @NonNull
    @Override
    public Mode getAuthenticationMode() {
        return Mode.AFTER_CONNECT;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected boolean doAuthenticate() {
        final SSHUserPrivateKey user = getUser();
        final String username = getUsername();
        final String originalUsername = getConnection().getUsername();

        for (String key : getUser().getPrivateKeys()) {
            try {
//                KeyPairResourceParser parser = KeyPairResourceParser.aggregate(
//                    BouncyCastleKeyPairResourceParser.INSTANCE,
//                    DSSPEMResourceKeyPairParser.INSTANCE,
//                    ECDSAPEMResourceKeyPairParser.INSTANCE,
//                    Ed25519PEMResourceKeyParser.INSTANCE,
//                    OpenSSHKeyPairResourceParser.INSTANCE,
//                    PEMResourceParserUtils.PROXY,
//                    PKCS8PEMResourceKeyPairParser.INSTANCE,
//                    RSAPEMResourceKeyPairParser.INSTANCE);
//                StringResource keyResource = new StringResource(key);
//                List<String> lines = Arrays.asList(key.split("\n"));
//                if(parser.canExtractKeyPairs(keyResource, lines))) {
//                    parser.loadKeyPairs(null, keyResource, user.getPassphrase() == null ? null
//                            : FilePasswordProvider.of(user.getPassphrase().getPlainText()), lines)
//                        .forEach(keyPair -> getConnection().addPublicKeyIdentity(keyPair));
//                    AuthFuture future = getConnection().auth();
//                    future.await(60, TimeUnit.SECONDS);
//                    if (future.isSuccess()) {
//                        return true;
//                    }
//                }

                KeyPairResourceLoader parser = SecurityUtils.getKeyPairResourceParser();

                StringResource keyResource = new StringResource(key);
                List<String> lines = Arrays.asList(key.split("\n"));
                Secret passphrase = user.getPassphrase();
                parser.loadKeyPairs(null, keyResource, passphrase == null ? null
                        : FilePasswordProvider.of(passphrase.getPlainText()), lines)
                    .forEach(keyPair -> getConnection().addPublicKeyIdentity(keyPair));
                getConnection().setUsername(username);
                return getConnection().auth().verify(MinaConnector.authTimeout, TimeUnit.SECONDS).isSuccess();
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Could not authenticate due to I/O issue", e);
            } catch (GeneralSecurityException e) {
                LOGGER.log(Level.WARNING, "Could not authenticate because unrecoverable key pair", e);
            } finally {
                getConnection().setUsername(originalUsername);
            }
        }
        return false;
    }

    public static class StringResource extends AbstractIoResource<String> {

        public StringResource(String key) {
            super(String.class, key);
        }

        @Override
        public InputStream openInputStream() {
            return new ByteArrayInputStream(this.getResourceValue().getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * {@inheritDoc}
     */
    @Extension
    public static class Factory extends SSHAuthenticatorFactory {

        /**
         * {@inheritDoc}
         */
        @Nullable
        @Override
        protected <C, U extends StandardUsernameCredentials> SSHAuthenticator<C, U> newInstance(@NonNull C connection,
                                                                                                @NonNull U user) {
            return newInstance(connection, user, null);
        }


        /**
         * {@inheritDoc}
         */
        @Nullable
        @Override
        @SuppressWarnings("unchecked")
        protected <C, U extends StandardUsernameCredentials> SSHAuthenticator<C, U> newInstance(@NonNull C connection,
                                                                                                @NonNull U user,
                                                                                                @CheckForNull String
                                                                                                    username) {
            if (supports(connection.getClass(), user.getClass())) {
                return (SSHAuthenticator<C, U>) new MinaSSHPublicKeyAuthenticator(
                    (ClientSession) connection,
                    (SSHUserPrivateKey) user,
                    username
                );
            }
            return null;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        protected <C, U extends StandardUsernameCredentials> boolean supports(@NonNull Class<C> connectionClass,
                                                                              @NonNull Class<U> userClass) {
            return ClientSession.class.isAssignableFrom(connectionClass)
                && SSHUserPrivateKey.class.isAssignableFrom(userClass);
        }

        private static final long serialVersionUID = 1L;
    }
}
