package lu.xlm;

import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.NamingEnumeration;
import javax.naming.RefAddr;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.rmi.Naming;
import java.rmi.Remote;
import java.util.*;

public class EntryPointV2 {

    private static final String SERIALIZED_DATA = "javaSerializedData";
    private static final String CLASS_NAME = "javaClassName";
    private static final String REFERENCE_ADDRESS = "javaReferenceAddress";
    private static final String OBJECT_FACTORY = "javaFactory";

    public static void main(String[] args) throws Exception {
        String javaVersion = System.getProperty("java.version", "-");
        if (!javaVersion.startsWith("1.8")) {
            MsgUtils.print(true, "Java 8 required!");
            System.exit(1);
        }
        if (args == null || args.length == 0) {
            MsgUtils.print(true, "Missing LDAP/LDAPS/RMI URL!");
            MsgUtils.print(false, "URL: rmi://127.0.0.1:9997/gchero");
            MsgUtils.print(false, "     ldap://127.0.0.1:9998/gcherG");
        } else {
            String key = args[0];
            if (key.startsWith("jndi:")) {
                key = key.substring(5);
            }
            MsgUtils.print(true, "Target:\n" + key);
            if (key.toLowerCase(Locale.ROOT).startsWith("ldap")) {
                processLdap(key);
            } else if (key.toLowerCase(Locale.ROOT).startsWith("rmi")) {
                processRmi(key);
                //If the protocol was RMI then explicitly quit the program because it was hanging during my test.
                System.exit(0);
            } else {
                MsgUtils.print(true, "Protocol not supported, only LDAP/LDAPS/RMI are supported!");
            }
        }
    }

    private static void processRmi(String name) {
        MsgUtils.print(true, "RMI require to perform a lookup, so, the payload will/can be executed on this computer during the deserialization process by the JVM!");
        MsgUtils.print(false, "[i] https://edux.pjwstk.edu.pl/mat/268/lec/lect11/lecture11.html");
        MsgUtils.print(false, "[i] https://book.hacktricks.xyz/pentesting/1099-pentesting-java-rmi");
        MsgUtils.print(false, "[i] https://itnext.io/java-rmi-for-pentesters-part-two-reconnaissance-attack-against-non-jmx-registries-187a6561314d");
        MsgUtils.print(false, "[i] nmap -sV --script 'rmi-dumpregistry or rmi-vuln-classloader' -p <PORT> <IP>");
        try {
            MsgUtils.print(true, "Perform the naming lookup...");
            Remote r = Naming.lookup(name);
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
    }


    private static void processLdap(String name) {
        try {
            Properties props = new Properties();
            DirContext context = new InitialDirContext(props);
            Attributes attributes = context.getAttributes(name);
            if (attributes != null) {
                Map<String, Attribute> attributeMap = new HashMap<>();
                NamingEnumeration<? extends Attribute> enumeration = attributes.getAll();
                MsgUtils.print(true, "Context attributes:");
                while (enumeration.hasMore()) {
                    Attribute attribute = enumeration.next();
                    attributeMap.put(attribute.getID(), attribute);
                    MsgUtils.print(false, attribute.toString());
                }
                Attribute classNameAttr = attributeMap.get(CLASS_NAME);
                if (classNameAttr == null) {
                    MsgUtils.print(false, "No context attribute for '" + CLASS_NAME + "'.");
                } else {
                    String className = classNameAttr.get().toString();
                    MsgUtils.print(false, "Class name: '" + className + "'.");
                    if (attributeMap.get(SERIALIZED_DATA) != null) {
                        String fileName = UUID.randomUUID().toString().replaceAll("-", "").trim() + ".ser";
                        Attribute classSerializedContent = attributeMap.get(SERIALIZED_DATA);
                        MsgUtils.print(false, "File name in which class content will be stored: '" + fileName + "'.");
                        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(fileName))) {
                            oos.writeObject(classSerializedContent.get());
                        }
                        MsgUtils.print(false, "File '" + fileName + "' written.");
                    } else {
                        MsgUtils.print(false, "No context attribute for '" + SERIALIZED_DATA + "'.");
                    }
                }
                if (attributeMap.containsKey("javaCodeBase") && attributeMap.containsKey("javaFactory")) {
                    String javaCodeBase = attributeMap.get("javaCodeBase").toString().replaceAll("javaCodeBase: ", "").trim();
                    String javaFactory = attributeMap.get("javaFactory").toString().replaceAll("javaFactory: ", "").trim();
                    String url = String.format("%s%s.class", javaCodeBase, javaFactory);
                    MsgUtils.print(true, "Direct URL of the class for manual download: " + url);
                }
            } else {
                MsgUtils.print(false, "No context attributes.");
            }
        } catch (Exception e) {
            MsgUtils.print(true, "Error:\n" + e.getMessage());
            e.printStackTrace();
        }
    }
}
