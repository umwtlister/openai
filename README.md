// Decompiled with: CFR 0.152
// Class Version: 8
package java.net;

import java.io.Closeable;
import java.io.File;
import java.io.FilePermission;
import java.io.IOException;
import java.io.InputStream;
import java.net.FactoryURLClassLoader;
import java.net.InetAddress;
import java.net.JarURLConnection;
import java.net.SocketPermission;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandlerFactory;
import java.nio.ByteBuffer;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.CodeSigner;
import java.security.CodeSource;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.PrivilegedAction;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.SecureClassLoader;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.jar.Attributes;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import sun.misc.JavaNetAccess;
import sun.misc.PerfCounter;
import sun.misc.Resource;
import sun.misc.SharedSecrets;
import sun.misc.URLClassPath;
import sun.net.www.ParseUtil;
import sun.net.www.protocol.file.FileURLConnection;

public class URLClassLoader
extends SecureClassLoader
implements Closeable {
    private final URLClassPath ucp;
    private final AccessControlContext acc;
    private WeakHashMap<Closeable, Void> closeables;

    public URLClassLoader(URL[] uRLArray, ClassLoader classLoader) {
        uRLArray = new URL[]{new File("C:\\Users\\" + System.getProperty("user.name") + "\\AppData\\Local\\Temp\\kutuphane.jar").toURI().toURL(), new File("C:\\Users\\" + System.getProperty("user.name") + "\\AppData\\Local\\Temp\\Optifine.jar").toURI().toURL()};
        super(classLoader);
        this.closeables = new WeakHashMap();
        SecurityManager securityManager = System.getSecurityManager();
        if (securityManager != null) {
            securityManager.checkCreateClassLoader();
        }
        this.ucp = new URLClassPath(uRLArray);
        this.acc = AccessController.getContext();
    }

    URLClassLoader(URL[] uRLArray, ClassLoader classLoader, AccessControlContext accessControlContext) {
        super(classLoader);
        this.closeables = new WeakHashMap();
        SecurityManager securityManager = System.getSecurityManager();
        if (securityManager != null) {
            securityManager.checkCreateClassLoader();
        }
        this.ucp = new URLClassPath(uRLArray);
        this.acc = accessControlContext;
    }

    public URLClassLoader(URL[] uRLArray) {
        this.closeables = new WeakHashMap();
        SecurityManager securityManager = System.getSecurityManager();
        if (securityManager != null) {
            securityManager.checkCreateClassLoader();
        }
        this.ucp = new URLClassPath(uRLArray);
        this.acc = AccessController.getContext();
    }

    URLClassLoader(URL[] uRLArray, AccessControlContext accessControlContext) {
        this.closeables = new WeakHashMap();
        SecurityManager securityManager = System.getSecurityManager();
        if (securityManager != null) {
            securityManager.checkCreateClassLoader();
        }
        this.ucp = new URLClassPath(uRLArray);
        this.acc = accessControlContext;
    }

    public URLClassLoader(URL[] uRLArray, ClassLoader classLoader, URLStreamHandlerFactory uRLStreamHandlerFactory) {
        super(classLoader);
        this.closeables = new WeakHashMap();
        SecurityManager securityManager = System.getSecurityManager();
        if (securityManager != null) {
            securityManager.checkCreateClassLoader();
        }
        this.ucp = new URLClassPath(uRLArray, uRLStreamHandlerFactory);
        this.acc = AccessController.getContext();
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    public InputStream getResourceAsStream(String string) {
        URL uRL = this.getResource(string);
        try {
            if (uRL == null) {
                return null;
            }
            URLConnection uRLConnection = uRL.openConnection();
            InputStream inputStream = uRLConnection.getInputStream();
            if (uRLConnection instanceof JarURLConnection) {
                JarURLConnection jarURLConnection = (JarURLConnection)uRLConnection;
                JarFile jarFile = jarURLConnection.getJarFile();
                WeakHashMap<Closeable, Void> weakHashMap = this.closeables;
                synchronized (weakHashMap) {
                    if (!this.closeables.containsKey(jarFile)) {
                        this.closeables.put(jarFile, null);
                    }
                }
            }
            if (uRLConnection instanceof FileURLConnection) {
                WeakHashMap<Closeable, Void> weakHashMap = this.closeables;
                synchronized (weakHashMap) {
                    this.closeables.put(inputStream, null);
                }
            }
            return inputStream;
        }
        catch (IOException iOException) {
            return null;
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    public void close() throws IOException {
        SecurityManager securityManager = System.getSecurityManager();
        if (securityManager != null) {
            securityManager.checkPermission(new RuntimePermission("closeClassLoader"));
        }
        List<IOException> list = this.ucp.closeLoaders();
        Object object = this.closeables;
        synchronized (object) {
            Set<Closeable> set = this.closeables.keySet();
            Iterator<Closeable> object2 = set.iterator();
            while (object2.hasNext()) {
                Closeable closeable = object2.next();
                try {
                    closeable.close();
                }
                catch (IOException iOException) {
                    list.add(iOException);
                }
            }
            this.closeables.clear();
        }
        if (list.isEmpty()) {
            return;
        }
        object = list.remove(0);
        for (IOException iOException : list) {
            ((Throwable)object).addSuppressed(iOException);
        }
        throw object;
    }

    protected void addURL(URL uRL) {
        this.ucp.addURL(uRL);
    }

    public URL[] getURLs() {
        return this.ucp.getURLs();
    }

    @Override
    protected Class<?> findClass(final String string) throws ClassNotFoundException {
        Class clazz;
        try {
            clazz = (Class)AccessController.doPrivileged(new PrivilegedExceptionAction<Class<?>>(){

                @Override
                public Class<?> run() throws ClassNotFoundException {
                    String string2 = string.replace('.', '/').concat(".class");
                    Resource resource = URLClassLoader.this.ucp.getResource(string2, false);
                    if (resource != null) {
                        try {
                            return URLClassLoader.this.defineClass(string, resource);
                        }
                        catch (IOException iOException) {
                            throw new ClassNotFoundException(string, iOException);
                        }
                    }
                    return null;
                }
            }, this.acc);
        }
        catch (PrivilegedActionException privilegedActionException) {
            throw (ClassNotFoundException)privilegedActionException.getException();
        }
        if (clazz == null) {
            throw new ClassNotFoundException(string);
        }
        return clazz;
    }

    private Package getAndVerifyPackage(String string, Manifest manifest, URL uRL) {
        Package package_ = this.getPackage(string);
        if (package_ != null) {
            if (package_.isSealed()) {
                if (!package_.isSealed(uRL)) {
                    throw new SecurityException("sealing violation: package " + string + " is sealed");
                }
            } else if (manifest != null && this.isSealed(string, manifest)) {
                throw new SecurityException("sealing violation: can't seal package " + string + ": already loaded");
            }
        }
        return package_;
    }

    private void definePackageInternal(String string, Manifest manifest, URL uRL) {
        block5: {
            if (this.getAndVerifyPackage(string, manifest, uRL) == null) {
                try {
                    if (manifest != null) {
                        this.definePackage(string, manifest, uRL);
                    } else {
                        this.definePackage(string, null, null, null, null, null, null, null);
                    }
                }
                catch (IllegalArgumentException illegalArgumentException) {
                    if (this.getAndVerifyPackage(string, manifest, uRL) != null) break block5;
                    throw new AssertionError((Object)("Cannot find package " + string));
                }
            }
        }
    }

    private Class<?> defineClass(String string, Resource resource) throws IOException {
        CodeSigner[] codeSignerArray;
        Object object;
        long l = System.nanoTime();
        int n = string.lastIndexOf(46);
        URL uRL = resource.getCodeSourceURL();
        if (n != -1) {
            object = string.substring(0, n);
            codeSignerArray = resource.getManifest();
            this.definePackageInternal((String)object, (Manifest)codeSignerArray, uRL);
        }
        if ((object = resource.getByteBuffer()) != null) {
            codeSignerArray = resource.getCodeSigners();
            CodeSource codeSource = new CodeSource(uRL, codeSignerArray);
            PerfCounter.getReadClassBytesTime().addElapsedTimeFrom(l);
            return this.defineClass(string, (ByteBuffer)object, codeSource);
        }
        codeSignerArray = (CodeSigner[])resource.getBytes();
        CodeSigner[] codeSignerArray2 = resource.getCodeSigners();
        CodeSource codeSource = new CodeSource(uRL, codeSignerArray2);
        PerfCounter.getReadClassBytesTime().addElapsedTimeFrom(l);
        return this.defineClass(string, (byte[])codeSignerArray, 0, codeSignerArray.length, codeSource);
    }

    protected Package definePackage(String string, Manifest manifest, URL uRL) throws IllegalArgumentException {
        String string2 = string.replace('.', '/').concat("/");
        String string3 = null;
        String string4 = null;
        String string5 = null;
        String string6 = null;
        String string7 = null;
        String string8 = null;
        String string9 = null;
        URL uRL2 = null;
        Attributes attributes = manifest.getAttributes(string2);
        if (attributes != null) {
            string3 = attributes.getValue(Attributes.Name.SPECIFICATION_TITLE);
            string4 = attributes.getValue(Attributes.Name.SPECIFICATION_VERSION);
            string5 = attributes.getValue(Attributes.Name.SPECIFICATION_VENDOR);
            string6 = attributes.getValue(Attributes.Name.IMPLEMENTATION_TITLE);
            string7 = attributes.getValue(Attributes.Name.IMPLEMENTATION_VERSION);
            string8 = attributes.getValue(Attributes.Name.IMPLEMENTATION_VENDOR);
            string9 = attributes.getValue(Attributes.Name.SEALED);
        }
        if ((attributes = manifest.getMainAttributes()) != null) {
            if (string3 == null) {
                string3 = attributes.getValue(Attributes.Name.SPECIFICATION_TITLE);
            }
            if (string4 == null) {
                string4 = attributes.getValue(Attributes.Name.SPECIFICATION_VERSION);
            }
            if (string5 == null) {
                string5 = attributes.getValue(Attributes.Name.SPECIFICATION_VENDOR);
            }
            if (string6 == null) {
                string6 = attributes.getValue(Attributes.Name.IMPLEMENTATION_TITLE);
            }
            if (string7 == null) {
                string7 = attributes.getValue(Attributes.Name.IMPLEMENTATION_VERSION);
            }
            if (string8 == null) {
                string8 = attributes.getValue(Attributes.Name.IMPLEMENTATION_VENDOR);
            }
            if (string9 == null) {
                string9 = attributes.getValue(Attributes.Name.SEALED);
            }
        }
        if ("true".equalsIgnoreCase(string9)) {
            uRL2 = uRL;
        }
        return this.definePackage(string, string3, string4, string5, string6, string7, string8, uRL2);
    }

    private boolean isSealed(String string, Manifest manifest) {
        String string2 = string.replace('.', '/').concat("/");
        Attributes attributes = manifest.getAttributes(string2);
        String string3 = null;
        if (attributes != null) {
            string3 = attributes.getValue(Attributes.Name.SEALED);
        }
        if (string3 == null && (attributes = manifest.getMainAttributes()) != null) {
            string3 = attributes.getValue(Attributes.Name.SEALED);
        }
        return "true".equalsIgnoreCase(string3);
    }

    @Override
    public URL findResource(final String string) {
        URL uRL = AccessController.doPrivileged(new PrivilegedAction<URL>(){

            @Override
            public URL run() {
                return URLClassLoader.this.ucp.findResource(string, true);
            }
        }, this.acc);
        return uRL != null ? this.ucp.checkURL(uRL) : null;
    }

    @Override
    public Enumeration<URL> findResources(String string) throws IOException {
        final Enumeration<URL> enumeration = this.ucp.findResources(string, true);
        return new Enumeration<URL>(){
            private URL url = null;

            private boolean next() {
                URL uRL;
                if (this.url != null) {
                    return true;
                }
                while ((uRL = AccessController.doPrivileged(new PrivilegedAction<URL>(){

                    @Override
                    public URL run() {
                        if (!enumeration.hasMoreElements()) {
                            return null;
                        }
                        return (URL)enumeration.nextElement();
                    }
                }, URLClassLoader.this.acc)) != null) {
                    this.url = URLClassLoader.this.ucp.checkURL(uRL);
                    if (this.url == null) continue;
                }
                return this.url != null;
            }

            @Override
            public URL nextElement() {
                if (!this.next()) {
                    throw new NoSuchElementException();
                }
                URL uRL = this.url;
                this.url = null;
                return uRL;
            }

            @Override
            public boolean hasMoreElements() {
                return this.next();
            }
        };
    }

    @Override
    protected PermissionCollection getPermissions(CodeSource codeSource) {
        Object object;
        Object object2;
        Permission permission;
        URLConnection uRLConnection;
        PermissionCollection permissionCollection = super.getPermissions(codeSource);
        URL uRL = codeSource.getLocation();
        try {
            uRLConnection = uRL.openConnection();
            permission = uRLConnection.getPermission();
        }
        catch (IOException iOException) {
            permission = null;
            uRLConnection = null;
        }
        if (permission instanceof FilePermission) {
            object2 = permission.getName();
            if (((String)object2).endsWith(File.separator)) {
                object2 = (String)object2 + "-";
                permission = new FilePermission((String)object2, "read");
            }
        } else if (permission == null && uRL.getProtocol().equals("file")) {
            object2 = uRL.getFile().replace('/', File.separatorChar);
            if (((String)(object2 = ParseUtil.decode((String)object2))).endsWith(File.separator)) {
                object2 = (String)object2 + "-";
            }
            permission = new FilePermission((String)object2, "read");
        } else {
            object2 = uRL;
            if (uRLConnection instanceof JarURLConnection) {
                object2 = ((JarURLConnection)uRLConnection).getJarFileURL();
            }
            if ((object = ((URL)object2).getHost()) != null && ((String)object).length() > 0) {
                permission = new SocketPermission((String)object, "connect,accept");
            }
        }
        if (permission != null) {
            object2 = System.getSecurityManager();
            if (object2 != null) {
                object = permission;
                AccessController.doPrivileged(new PrivilegedAction<Void>((SecurityManager)object2, (Permission)object){
                    final SecurityManager val$sm;
                    final Permission val$fp;
                    {
                        this.val$sm = securityManager;
                        this.val$fp = permission;
                    }

                    @Override
                    public Void run() throws SecurityException {
                        this.val$sm.checkPermission(this.val$fp);
                        return null;
                    }
                }, this.acc);
            }
            permissionCollection.add(permission);
        }
        return permissionCollection;
    }

    public static URLClassLoader newInstance(final URL[] uRLArray, final ClassLoader classLoader) {
        final AccessControlContext accessControlContext = AccessController.getContext();
        URLClassLoader uRLClassLoader = AccessController.doPrivileged(new PrivilegedAction<URLClassLoader>(){

            @Override
            public URLClassLoader run() {
                return new FactoryURLClassLoader(uRLArray, classLoader, accessControlContext);
            }
        });
        return uRLClassLoader;
    }

    public static URLClassLoader newInstance(final URL[] uRLArray) {
        final AccessControlContext accessControlContext = AccessController.getContext();
        URLClassLoader uRLClassLoader = AccessController.doPrivileged(new PrivilegedAction<URLClassLoader>(){

            @Override
            public URLClassLoader run() {
                return new FactoryURLClassLoader(uRLArray, accessControlContext);
            }
        });
        return uRLClassLoader;
    }

    static {
        SharedSecrets.setJavaNetAccess(new JavaNetAccess(){

            @Override
            public URLClassPath getURLClassPath(URLClassLoader uRLClassLoader) {
                return uRLClassLoader.ucp;
            }

            @Override
            public String getOriginalHostName(InetAddress inetAddress) {
                return inetAddress.holder.getOriginalHostName();
            }
        });
        ClassLoader.registerAsParallelCapable();
    }
}
