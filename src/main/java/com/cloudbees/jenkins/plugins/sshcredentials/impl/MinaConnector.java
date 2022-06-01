package com.cloudbees.jenkins.plugins.sshcredentials.impl;

import com.cloudbees.jenkins.plugins.sshcredentials.SSHAuthenticatorException;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

public class MinaConnector {

    static /*almost final*/ int connectTimeout = Integer.parseInt(System.getProperty(MinaConnector.class.getName() + ".connectTimeout", "30"));
    static /*almost final*/ int authTimeout = Integer.parseInt(System.getProperty(MinaConnector.class.getName() + ".authTimeout", "30"));

    private final SshClient sshClient;
    private final String host;
    private final int port;
    private ClientSession session = null;
    private final String username;

    public MinaConnector(String username, String host, int port) {
        this(SshClient.setUpDefaultClient(), username, host, port);
    }

    public MinaConnector(SshClient sshClient, String username, String host, int port) {
        this.host = host;
        this.sshClient = sshClient;
        this.port = port;
        this.username = username;
    }

    public SshClient getSshClient() {
        return sshClient;
    }

    public synchronized boolean hasSession() {
        return session != null;
    }

    public synchronized ClientSession getSession() {
        if (!sshClient.isStarted()) {
            sshClient.start();
        }
        if (!hasSession()) {
            try {
                session = sshClient.connect(username, host, port)
                    .verify(connectTimeout, TimeUnit.SECONDS)
                    .getClientSession();
            } catch (IOException e) {
                throw new SSHAuthenticatorException(e);
            }
        }
        return session;
    }

    public synchronized void close() {
        if (session != null) {
            session.close(true);
            session = null;
        }
        sshClient.stop();
    }
}
