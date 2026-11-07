import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.Environment;
import org.apache.sshd.server.ExitCallback;
import org.apache.sshd.server.auth.password.UserAuthPasswordFactory;
import org.apache.sshd.server.channel.ChannelSession;
import org.apache.sshd.server.command.Command;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;

public final class Server {
    public static void main(String[] args) throws Exception {
        SshServer server = SshServer.setUpDefaultServer();
        server.setPort(22);
        SimpleGeneratorHostKeyProvider keys = new SimpleGeneratorHostKeyProvider(Path.of("/app/hostkey.ser"));
        keys.setAlgorithm("EC");
        keys.setKeySize(256);
        // Generate before listening so the first KEXINIT is not delayed by key generation.
        keys.loadKeys(null).iterator().next();
        server.setKeyPairProvider(keys);
        server.setUserAuthFactories(List.of(UserAuthPasswordFactory.INSTANCE));
        server.setPasswordAuthenticator((user, password, session) ->
                "test".equals(user) && "test".equals(password));
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
