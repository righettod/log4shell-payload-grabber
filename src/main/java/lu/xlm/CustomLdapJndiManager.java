package lu.xlm;

import org.apache.logging.log4j.core.appender.AbstractManager;
import org.apache.logging.log4j.core.appender.ManagerFactory;
import org.apache.logging.log4j.core.util.JndiCloser;
import org.apache.logging.log4j.util.PropertiesUtil;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Custom JndiManager using impl from original "JndiManager" to benefits from its lookup context setuped.
 * <p>
 * The goal is to access to the lookup context directly.
 *
 * @see "https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/net/JndiManager.java"
 */
public class CustomLdapJndiManager extends AbstractManager {


    public static final String ALLOWED_HOSTS = "allowedLdapHosts";
    public static final String ALLOWED_CLASSES = "allowedLdapClasses";
    public static final String ALLOWED_PROTOCOLS = "allowedJndiProtocols";

    private static final JndiManagerFactory FACTORY = new JndiManagerFactory();
    private static final String PREFIX = "log4j2.";
    private static final String LDAP = "ldap";
    private static final String LDAPS = "ldaps";
    private static final String JAVA = "java";
    private static final List<String> permanentAllowedHosts = new ArrayList();
    private static final List<String> permanentAllowedClasses = Arrays.asList(Boolean.class.getName(),
            Byte.class.getName(), Character.class.getName(), Double.class.getName(), Float.class.getName(),
            Integer.class.getName(), Long.class.getName(), Short.class.getName(), String.class.getName());
    private static final List<String> permanentAllowedProtocols = Arrays.asList(JAVA, LDAP, LDAPS);
    private static final String SERIALIZED_DATA = "javaSerializedData";
    private static final String CLASS_NAME = "javaClassName";
    private static final String REFERENCE_ADDRESS = "javaReferenceAddress";
    private static final String OBJECT_FACTORY = "javaFactory";
    private List<String> allowedHosts;
    private List<String> allowedClasses;
    private final List<String> allowedProtocols;

    private DirContext context;

    public static boolean isJndiEnabled() {
        return true;
    }

    private CustomLdapJndiManager(final String name, final DirContext context, final List<String> allowedHosts,
                                  final List<String> allowedClasses, final List<String> allowedProtocols) {
        super(null, name);
        this.context = context;
        this.allowedHosts = allowedHosts;
        this.allowedClasses = allowedClasses;
        this.allowedProtocols = allowedProtocols;
    }

    private CustomLdapJndiManager(final String name) {
        super(null, name);
        this.context = null;
        this.allowedProtocols = null;
        this.allowedClasses = null;
        this.allowedHosts = null;
    }

    /**
     * Gets the default JndiManager using the default {@link javax.naming.InitialContext}.
     *
     * @return the default JndiManager
     */
    public static CustomLdapJndiManager getDefaultManager() {
        return getManager(CustomLdapJndiManager.class.getName(), FACTORY, null);
    }

    /**
     * Gets a named JndiManager using the default {@link javax.naming.InitialContext}.
     *
     * @param name the name of the JndiManager instance to create or use if available
     * @return a default JndiManager
     */
    public static CustomLdapJndiManager getDefaultManager(final String name) {
        return getManager(name, FACTORY, null);
    }

    /**
     * Gets a JndiManager with the provided configuration information.
     *
     * @param initialContextFactoryName Fully qualified class name of an implementation of
     *                                  {@link javax.naming.spi.InitialContextFactory}.
     * @param providerURL               The provider URL to use for the JNDI connection (specific to the above factory).
     * @param urlPkgPrefixes            A colon-separated list of package prefixes for the class name of the factory
     *                                  class that will create a URL context factory
     * @param securityPrincipal         The name of the identity of the Principal.
     * @param securityCredentials       The security credentials of the Principal.
     * @param additionalProperties      Any additional JNDI environment properties to set or {@code null} for none.
     * @return the JndiManager for the provided parameters.
     */
    public static CustomLdapJndiManager getJndiManager(final String initialContextFactoryName,
                                                       final String providerURL,
                                                       final String urlPkgPrefixes,
                                                       final String securityPrincipal,
                                                       final String securityCredentials,
                                                       final Properties additionalProperties) {
        final Properties properties = createProperties(initialContextFactoryName, providerURL, urlPkgPrefixes,
                securityPrincipal, securityCredentials, additionalProperties);
        return getManager(createManagerName(), FACTORY, properties);
    }

    /**
     * Gets a JndiManager with the provided configuration information.
     *
     * @param properties JNDI properties, usually created by calling {@link #createProperties(String, String, String, String, String, Properties)}.
     * @return the JndiManager for the provided parameters.
     * @see #createProperties(String, String, String, String, String, Properties)
     * @since 2.9
     */
    public static CustomLdapJndiManager getJndiManager(final Properties properties) {
        return getManager(createManagerName(), FACTORY, properties);
    }

    private static String createManagerName() {
        return CustomLdapJndiManager.class.getName() + '@' + CustomLdapJndiManager.class.hashCode();
    }

    /**
     * Creates JNDI Properties with the provided configuration information.
     *
     * @param initialContextFactoryName Fully qualified class name of an implementation of {@link javax.naming.spi.InitialContextFactory}.
     * @param providerURL               The provider URL to use for the JNDI connection (specific to the above factory).
     * @param urlPkgPrefixes            A colon-separated list of package prefixes for the class name of the factory class that will create a
     *                                  URL context factory
     * @param securityPrincipal         The name of the identity of the Principal.
     * @param securityCredentials       The security credentials of the Principal.
     * @param additionalProperties      Any additional JNDI environment properties to set or {@code null} for none.
     * @return the Properties for the provided parameters.
     * @since 2.9
     */
    public static Properties createProperties(final String initialContextFactoryName, final String providerURL,
                                              final String urlPkgPrefixes, final String securityPrincipal, final String securityCredentials,
                                              final Properties additionalProperties) {
        if (initialContextFactoryName == null) {
            return null;
        }
        final Properties properties = new Properties();
        properties.setProperty(Context.INITIAL_CONTEXT_FACTORY, initialContextFactoryName);
        if (providerURL != null) {
            properties.setProperty(Context.PROVIDER_URL, providerURL);
        } else {
            LOGGER.warn("The JNDI InitialContextFactory class name [{}] was provided, but there was no associated "
                    + "provider URL. This is likely to cause problems.", initialContextFactoryName);
        }
        if (urlPkgPrefixes != null) {
            properties.setProperty(Context.URL_PKG_PREFIXES, urlPkgPrefixes);
        }
        if (securityPrincipal != null) {
            properties.setProperty(Context.SECURITY_PRINCIPAL, securityPrincipal);
            if (securityCredentials != null) {
                properties.setProperty(Context.SECURITY_CREDENTIALS, securityCredentials);
            } else {
                LOGGER.warn("A security principal [{}] was provided, but with no corresponding security credentials.",
                        securityPrincipal);
            }
        }
        if (additionalProperties != null) {
            properties.putAll(additionalProperties);
        }
        return properties;
    }

    @Override
    protected boolean releaseSub(final long timeout, final TimeUnit timeUnit) {
        return JndiCloser.closeSilently(this.context);
    }

    /**
     * Looks up a named object through this JNDI context.
     *
     * @param name name of the object to look up.
     * @param <T>  the type of the object.
     * @return the named object if it could be located.
     * @throws NamingException if a naming exception is encountered
     */
    @SuppressWarnings("unchecked")
    public synchronized <T> T lookup(final String name) throws NamingException {
        if (context == null) {
            MsgUtils.print(true, "Lookup context is NULL!");
            return null;
        }

        //--Begin of custom code
        //Code taken from
        //https://github.com/apache/logging-log4j2/blob/master/log4j-core/src/main/java/org/apache/logging/log4j/core/net/JndiManager.java#L221
        try {
            Attributes attributes = this.context.getAttributes(name);
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
                    MsgUtils.print(false, "Class name: " + className + "'.");
                    if (attributeMap.get(SERIALIZED_DATA) != null) {
                        String fileName = UUID.randomUUID().toString().replaceAll("-", "").trim() + ".ser";
                        Attribute classSerializedContent = attributeMap.get(SERIALIZED_DATA);
                        MsgUtils.print(false, "File name in which class content will be stored: " + fileName + "'.");
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

        //--End of custom code
        //return (T) this.context.lookup(name);
        return null;//Do not perform any lookup to prevent execution of the payload during the deserialization
    }

    private static class JndiManagerFactory implements ManagerFactory<CustomLdapJndiManager, Properties> {

        @Override
        public CustomLdapJndiManager createManager(final String name, final Properties data) {
            if (isJndiEnabled()) {
                String hosts = data != null ? data.getProperty(ALLOWED_HOSTS) : null;
                String classes = data != null ? data.getProperty(ALLOWED_CLASSES) : null;
                String protocols = data != null ? data.getProperty(ALLOWED_PROTOCOLS) : null;
                List<String> allowedHosts = new ArrayList<>();
                List<String> allowedClasses = new ArrayList<>();
                List<String> allowedProtocols = new ArrayList<>();
                addAll(hosts, allowedHosts, permanentAllowedHosts, ALLOWED_HOSTS, data);
                addAll(classes, allowedClasses, permanentAllowedClasses, ALLOWED_CLASSES, data);
                addAll(protocols, allowedProtocols, permanentAllowedProtocols, ALLOWED_PROTOCOLS, data);
                try {
                    return new CustomLdapJndiManager(name, new InitialDirContext(data), allowedHosts, allowedClasses,
                            allowedProtocols);
                } catch (final NamingException e) {
                    LOGGER.error("Error creating JNDI InitialContext.", e);
                    return null;
                }
            } else {
                return new CustomLdapJndiManager(name);
            }
        }

        private void addAll(String toSplit, List<String> list, List<String> permanentList, String propertyName,
                            Properties data) {
            if (toSplit != null) {
                list.addAll(Arrays.asList(toSplit.split("\\s*,\\s*")));
                data.remove(propertyName);
            }
            toSplit = PropertiesUtil.getProperties().getStringProperty(PREFIX + propertyName);
            if (toSplit != null) {
                list.addAll(Arrays.asList(toSplit.split("\\s*,\\s*")));
            }
            list.addAll(permanentList);
        }
    }

    @Override
    public String toString() {
        return "CustomJndiManager [context=" + context + ", count=" + count + "]";
    }
}
