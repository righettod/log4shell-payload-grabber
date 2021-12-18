package org.apache.logging.log4j.core.lookup;

import com.sun.jndi.rmi.registry.ReferenceWrapper;
import lu.xlm.CustomLdapJndiManager;
import lu.xlm.MsgUtils;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.config.plugins.Plugin;

import javax.naming.NamingException;
import javax.naming.RefAddr;
import java.rmi.Naming;
import java.rmi.Remote;
import java.util.Enumeration;
import java.util.Locale;

/**
 * Custom plugin used method from original "JndiLookup" to benefits from its lookup context initialized.
 *
 * @see "https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JndiLookup.java"
 */
@Plugin(name = "xlmjndi", category = StrLookup.CATEGORY)
public class CustomJndiLookup extends JndiLookup {

    /**
     * Override method using the same code just to access to the retrived object
     */
    @Override
    public String lookup(final LogEvent event, final String key) {
        if (key == null) {
            return null;
        }
        final String jndiName = convertJndiName(key);
        if (jndiName.toLowerCase(Locale.ROOT).startsWith("ldap")) {
            try (final CustomLdapJndiManager jndiManager = CustomLdapJndiManager.getDefaultManager()) {
                jndiManager.lookup(jndiName);
            } catch (final NamingException e) {
                e.printStackTrace();
            }
        } else if (jndiName.toLowerCase(Locale.ROOT).startsWith("rmi")) {
            MsgUtils.print(true, "RMI require to perform a lookup, so, the payload will/can be executed on this computer during the deserialization process by the JVM!");
            MsgUtils.print(false, "[i] https://edux.pjwstk.edu.pl/mat/268/lec/lect11/lecture11.html");
            MsgUtils.print(false, "[i] https://book.hacktricks.xyz/pentesting/1099-pentesting-java-rmi");
            MsgUtils.print(false, "[i] https://itnext.io/java-rmi-for-pentesters-part-two-reconnaissance-attack-against-non-jmx-registries-187a6561314d");
            MsgUtils.print(false, "[i] nmap -sV --script 'rmi-dumpregistry or rmi-vuln-classloader' -p <PORT> <IP>");
            try {
                MsgUtils.print(true, "Perform the naming lookup...");
                Remote r = Naming.lookup(jndiName);
                ReferenceWrapper ref = (ReferenceWrapper) r;
                MsgUtils.print(true, "Remote object infos:");
                if (ref != null) {
                    MsgUtils.print(false, "Class name: " + ref.getReference().getClassName());
                    MsgUtils.print(false, "Factory class name: " + ref.getReference().getFactoryClassName());
                    MsgUtils.print(false, "Factory class location: " + ref.getReference().getFactoryClassLocation());
                    if (ref.getReference().getAll() != null) {
                        Enumeration<RefAddr> refs = ref.getReference().getAll();
                        while (refs.hasMoreElements()) {
                            MsgUtils.print(false, "Ref: " + refs.nextElement().toString());
                        }
                    }
                    if (ref.getReference().getFactoryClassLocation() != null) {
                        String url = ref.getReference().getFactoryClassLocation().replaceAll("#", "") + ".class";
                        MsgUtils.print(true, "Direct URL of the class for manual download: " + url);
                    }
                }
            } catch (Exception e) {
                MsgUtils.print(true, "Error:\n" + e.getMessage());
                e.printStackTrace();
            }
        } else {
            MsgUtils.print(true, "Protocol not supported, only LDAP/LDAPS/RMI supported!");
        }
        return "";
    }

    /**
     * Convert the given JNDI name to the actual JNDI name to use.
     * Default implementation applies the "java:comp/env/" prefix
     * unless other scheme like "java:" is given.
     *
     * @param jndiName The name of the resource.
     * @return The fully qualified name to look up.
     */
    public static String convertJndiName(final String jndiName) {
        if (!jndiName.startsWith(CONTAINER_JNDI_RESOURCE_PATH_PREFIX) && jndiName.indexOf(':') == -1) {
            return CONTAINER_JNDI_RESOURCE_PATH_PREFIX + jndiName;
        }
        return jndiName;
    }
}
