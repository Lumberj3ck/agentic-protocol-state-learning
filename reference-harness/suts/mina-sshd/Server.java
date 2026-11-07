// Apache MINA SSHD server for stream B1. Adapted from vendor/agentic-protocol-state-learning/targets/mina-sshd (Apache-2.0).
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory;
import org.apache.sshd.server.auth.pubkey.UserAuthPublicKeyFactory;
import org.apache.sshd.server.auth.pubkey.AuthorizedKeyEntriesPublickeyAuthenticator;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.common.config.keys.AuthorizedKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;

public final class Server {
    public static void main(String[] args) throws Exception {
        SshServer server = SshServer.setUpDefaultServer();
        server.setPort(22);
        SimpleGeneratorHostKeyProvider keys = new SimpleGeneratorHostKeyProvider(Path.of("/app/hostkey.ser"));
        keys.setAlgorithm("RSA");
        keys.setKeySize(3072);
        keys.loadKeys(null).iterator().next();
        server.setKeyPairProvider(keys);
        server.setUserAuthFactories(List.of(UserAuthPasswordFactory.INSTANCE, UserAuthPublicKeyFactory.INSTANCE));
        server.setPasswordAuthenticator((user, password, session) ->
                "tester".equals(user) && "correct-horse-battery".equals(password));
        // authorized_keys is re-read on every attempt so the key can be installed after start
        server.setPublickeyAuthenticator((user, key, session) -> {
            if (!"tester".equals(user)) return false;
            try {
                var entries = AuthorizedKeyEntry.readAuthorizedKeys(Path.of("/etc/psm/authorized_keys"));
                return new AuthorizedKeyEntriesPublickeyAuthenticator(
                        "psm", null, entries, PublicKeyEntryResolver.IGNORING).authenticate(user, key, session);
            } catch (Exception e) {
                return false;
            }
        });
        server.setCommandFactory((channel, command) -> new SuccessfulCommand());
        server.start();
        new CountDownLatch(1).await();
    }

    private static final class SuccessfulCommand implements Command {
        private ExitCallback callback;
        public void setInputStream(InputStream in) {}
        public void setOutputStream(OutputStream out) {}
        public void setErrorStream(OutputStream err) {}
        public void setExitCallback(ExitCallback callback) { this.callback = callback; }
        public void start(ChannelSession channel, Environment environment) { callback.onExit(0); }
        public void destroy(ChannelSession channel) {}
    }
}
