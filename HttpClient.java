import java.io.*;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.Map.Entry;
import java.util.zip.GZIPInputStream;

import javax.net.ssl.*;

import org.apache.commons.io.IOUtils;
import org.apache.commons.codec.binary.Base64;

public class HttpClient
{

    private int lastResponseCode;
    private Map<String, List<String>> responseHeaders;

    public Map<String, List<String>> getResponseHeaders() {
        return responseHeaders;
    }

    public void setResponseHeaders(Map<String, List<String>> responseHeaders) {
        this.responseHeaders = responseHeaders;
    }

    public int getLastResponseCode() {
        return lastResponseCode;
    }

    public void setLastResponseCode(int lastResponseCode) {
        this.lastResponseCode = lastResponseCode;
    }

    public static class HttpClientSSLSocketFactory
            extends SSLSocketFactory
    {
        public SSLContext sslCtx = null;
        public Set<String> sslProtocols = new HashSet();
        public Set<String> sslCiphers = new HashSet();

        URL url = null;

        public URL getUrl() {
            return url;
        }

        public void setUrl(URL url) {
            this.url = url;
        }

        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
                throws IOException
        {
            SSLSocket socket = (SSLSocket) sslCtx.getSocketFactory().createSocket(address, port, localAddress, localPort);
            setSocketOptions(socket);
            return socket;
        }

        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
                throws IOException, UnknownHostException
        {
            SSLSocket socket = (SSLSocket) sslCtx.getSocketFactory().createSocket(host, port, localHost, localPort);
            setSocketOptions(socket);
            return socket;
        }

        @Override
        public Socket createSocket(InetAddress host, int port)
                throws IOException
        {
            SSLSocket socket = (SSLSocket) sslCtx.getSocketFactory().createSocket(host, port);
            setSocketOptions(socket);
            return socket;
        }

        @Override
        public Socket createSocket(String host, int port)
                throws IOException,	UnknownHostException
        {
            SSLSocket socket = (SSLSocket) sslCtx.getSocketFactory().createSocket(host, port);
            setSocketOptions(socket);
            return socket;
        }

        @Override
        public String[] getSupportedCipherSuites()
        {
            return sslCiphers.toArray(new String[0]);
        }

        @Override
        public String[] getDefaultCipherSuites()
        {
            return sslCiphers.toArray(new String[0]);
        }

        @Override
        public Socket createSocket(Socket s, String host, int port, boolean autoClose)
                throws IOException
        {
            SSLSocket socket = (SSLSocket) sslCtx.getSocketFactory().createSocket(s, host, port, autoClose);
            setSocketOptions(socket);
            return socket;
        }

        void setSocketOptions(SSLSocket socket)
        {
            if(!sslProtocols.isEmpty())
            {
                socket.setEnabledProtocols(sslProtocols.toArray(new String[0]));
            }

            if(!sslCiphers.isEmpty())
            {
                socket.setEnabledCipherSuites(sslCiphers.toArray(new String[0]));
            }

            SSLParameters sslParameters = new SSLParameters();
            if(url!=null)
            {
                List sniHostNames = new ArrayList(1);
                sniHostNames.add(new SNIHostName(url.getHost()));
                sslParameters.setServerNames(sniHostNames);
            }
            socket.setSSLParameters(sslParameters);
        }
    }

    protected static final String HTTP_METHOD_POST = "POST";
    protected static final String HTTP_HEADER_ACCEPT_LANGUAGE = "Accept-Language";
    protected static final String HTTP_HEADER_ACCEPT_ENCODING = "Accept-Encoding";
    protected static final String HTTP_HEADER_ACCEPT = "Accept";
    protected static final String HTTP_HEADER_CONTENT_ENCODING = "Content-Encoding";
    protected static final String HTTP_HEADER_CONTENT_TYPE = "Content-Type";
    protected static final String HTTP_HEADER_CONTENT_LENGTH = "Content-Length";
    protected static final String ENCODING_GZIP = "gzip";

    public HttpClient() {}

    private SSLContext sslCtx = null;
    private String proxyUrl = null;
    private boolean acceptGzipEncoding = false;
    private String credential = null;
    private String contentType = "text/plain";
    private String acceptType = "text/plain";
    private Map<String, String> requestHeader = new HashMap();
    private Set<String> sslProtocols = new HashSet();
    private Set<String> sslCiphers = new HashSet();
    boolean followRedirects = false;
    int connectTimeout = -1;
    int readTimeout = -1;

    public boolean isFollowRedirects() {
        return followRedirects;
    }

    public void setFollowRedirects(boolean followRedirects) {
        this.followRedirects = followRedirects;
    }

    public int getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(int connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public int getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(int readTimeout) {
        this.readTimeout = readTimeout;
    }

    public boolean isAcceptGzipEncoding()
    {
        return acceptGzipEncoding;
    }

    public void setAcceptGzipEncoding(boolean acceptGzipEncoding)
    {
        this.acceptGzipEncoding = acceptGzipEncoding;
    }

    public String getCredential()
    {
        return credential;
    }

    public void setCredential(String credential)
    {
        this.credential = credential;
    }

    public String getContentType()
    {
        return contentType;
    }

    public void setContentType(String contentType)
    {
        this.contentType = contentType;
    }

    public String getAcceptType()
    {
        return acceptType;
    }

    public void setAcceptType(String acceptType)
    {
        this.acceptType = acceptType;
    }

    public Map<String, String> getRequestHeader()
    {
        return requestHeader;
    }

    public void setRequestHeader(Map<String, String> requestHeader)
    {
        this.requestHeader = requestHeader;
    }

    protected HttpURLConnection openConnection(String url)
            throws IOException
    {
        URLConnection con = null;
        if(proxyUrl!=null)
        {
            try
            {
                URI uri = URI.create(proxyUrl);
                if(uri.getScheme().startsWith("http"))
                {
                    con = new URL(url).openConnection(new Proxy(Proxy.Type.HTTP, new InetSocketAddress(uri.getHost(), uri.getPort())));
                }
                else
                if(uri.getScheme().startsWith("socks"))
                {
                    con = new URL(url).openConnection(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(uri.getHost(), uri.getPort())));
                }
            }
            catch(Exception xe)
            {
                con = new URL(url).openConnection();
            }
        }
        else
        {
            con = new URL(url).openConnection();
        }

        if (!(con instanceof HttpURLConnection)) {
            throw new IOException("Service URL [" + url + "] is not an HTTP URL");
        }
        return (HttpURLConnection) con;
    }

    protected void prepareConnection(HttpURLConnection con, String method, String contentType, int contentLength)
            throws IOException
    {
        con.setDoOutput(contentLength!=0);

        con.setRequestMethod((method == null) ? HTTP_METHOD_POST : method);

        if(this.requestHeader!=null && this.requestHeader.size()!=0)
        {
            for(Entry<String, String> _entry : this.requestHeader.entrySet())
            {
                con.setRequestProperty(_entry.getKey(), _entry.getValue());
            }
        }

        if(connectTimeout>0)
        {
            con.setConnectTimeout(connectTimeout);
        }

        if(readTimeout>0)
        {
            con.setReadTimeout(readTimeout);
        }

        if(contentType!=null)
        {
            con.setRequestProperty(HTTP_HEADER_CONTENT_TYPE, contentType);
        }

        if(acceptType!=null)
        {
            con.setRequestProperty(HTTP_HEADER_ACCEPT, acceptType);
        }

        con.setRequestProperty(HTTP_HEADER_CONTENT_LENGTH, Integer.toString(contentLength));

        if (isAcceptGzipEncoding()) {
            con.setRequestProperty(HTTP_HEADER_ACCEPT_ENCODING, ENCODING_GZIP);
        }

        if(credential!=null)
        {
            con.setRequestProperty("Authorization", "Basic "+ new String(Base64.encodeBase64String(credential.getBytes())));
        }

        con.setAllowUserInteraction(false);
        con.setInstanceFollowRedirects(this.followRedirects);

        if(con instanceof HttpsURLConnection)
        {
            if(sslCtx == null)
            {
                try
                {
                    sslCtx = SSLContext.getInstance("TLSv1.2");

                    sslCtx.init(new KeyManager[0], new TrustManager[] { new X509TrustManager()
                    {
                        public X509Certificate[] getAcceptedIssuers()
                        {
                            return null;
                        }

                        public void checkServerTrusted(X509Certificate[] arg0, String arg1)
                                throws CertificateException
                        {
                            // TODO Auto-generated method stub
                        }

                        public void checkClientTrusted(X509Certificate[] arg0, String arg1)
                                throws CertificateException
                        {
                            // TODO Auto-generated method stub
                        }
                    }}, null);
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                }
            }

            HttpsURLConnection scon = (HttpsURLConnection)con;
            scon.setHostnameVerifier(new HostnameVerifier()
            {
                public boolean verify(String arg0, SSLSession arg1)
                {
                    return true;
                }
            });

            HttpClientSSLSocketFactory sfact = new HttpClientSSLSocketFactory();
            sfact.sslCtx = sslCtx;
            sfact.sslProtocols = this.sslProtocols;
            sfact.sslCiphers = this.sslCiphers;
            sfact.setUrl(con.getURL());
            scon.setSSLSocketFactory(sfact);
        }

    }

    protected void writeRequestBody(HttpURLConnection con, ByteArrayOutputStream baos)
            throws IOException
    {
        baos.writeTo(con.getOutputStream());
    }

    protected void writeRequestBody(HttpURLConnection con, byte[] data)
            throws IOException
    {
        OutputStream os = con.getOutputStream();
        os.write(data);
        os.flush();
    }

    protected void validateResponse(HttpURLConnection con)
            throws IOException
    {
        this.responseHeaders = con.getHeaderFields();
		/*
		if (con.getResponseCode() >= 300) {
			throw new IOException(
					"Did not receive successful HTTP response: status code = " + con.getResponseCode() +
					", status message = [" + con.getResponseMessage() + "]");
		}
		*/
    }

    protected InputStream readResponseBody(HttpURLConnection con)
            throws IOException
    {
        this.lastResponseCode = con.getResponseCode();

        if (isGzipResponse(con)) {
            // GZIP response found - need to unzip.
            return new GZIPInputStream(con.getInputStream());
        }
        else {
            // Plain response found.
            try
            {
                return con.getInputStream();
            }
            catch(Exception _xe)
            {
                return con.getErrorStream();
            }
        }
    }

    protected boolean isGzipResponse(HttpURLConnection con)
    {
        String encodingHeader = con.getHeaderField(HTTP_HEADER_CONTENT_ENCODING);
        return (encodingHeader != null && encodingHeader.toLowerCase().indexOf(ENCODING_GZIP) != -1);
    }

    public void setLoginCredential(String name, String credential) {
        this.credential = name+":"+credential;
    }

    public Response executePostForm(String _url, Properties _form_data) throws Exception
    {
        this.setAcceptType("*/*");
        String _type = "application/x-www-form-urlencoded";
        StringBuilder _sb = new StringBuilder();
        for(String _key : _form_data.stringPropertyNames())
        {
            _sb.append("&");
            _sb.append(encodeUrl(_key.getBytes()));
            _sb.append("=");
            _sb.append(encodeUrl(_form_data.getProperty(_key).getBytes()));
        }
        return executeRequest(_url, "POST", _type, _sb.toString().substring(1));
    }

    public Response executeRequest(String url, String method, String contentType, String data)
            throws Exception
    {
        return executeRequest(url, method, contentType, (byte[]) (data != null ? data.getBytes() : null));
    }

    public Response executeRequest(String url, String method, String contentType, byte[] data)
            throws Exception
    {
        HttpURLConnection con = openConnection(url);
        prepareConnection(con, method, contentType, data!=null ? data.length : 0);

        if(requestHeader.size()>0)
        {
            for(Entry<String, String> entry : requestHeader.entrySet())
            {
                con.setRequestProperty(entry.getKey(), entry.getValue());
            }
        }

        if(data!=null && data.length!=0)
        {
            writeRequestBody(con, data);
        }
        else
        {
            con.connect();
        }
        validateResponse(con);

        Response _resp = new Response();
        InputStream responseBody = readResponseBody(con);
        _resp.body = IOUtils.toByteArray(responseBody);
        _resp.status = con.getResponseCode();
        _resp.headers.putAll(con.getHeaderFields());

        con.disconnect();
        return _resp;
    }

    public String getProxyUrl() {
        return proxyUrl;
    }

    public void setProxyUrl(String proxyUrl) {
        this.proxyUrl = proxyUrl;
    }

    public Set<String> getSslProtocols() {
        return sslProtocols;
    }

    public void setSslProtocols(Set<String> sslProtocols) {
        this.sslProtocols = sslProtocols;
    }

    public Set<String> getSslCiphers() {
        return sslCiphers;
    }

    public void setSslCiphers(Set<String> sslCiphers) {
        this.sslCiphers = sslCiphers;
    }

    public static void main(String[] args)
            throws Exception
    {
        HttpClient hc = new HttpClient();
        hc.setProxyUrl("http://127.0.0.1:3128/");
        hc.getSslProtocols().add("TLSv1.2");
        hc.getSslCiphers().add("TLS_RSA_WITH_AES_256_CBC_SHA256");

        Response res = hc.executeRequest("https://www.google.com/", "GET", null, "");
        System.out.println(res);
    }

    protected static final byte ESCAPE_CHAR = '%';
    private static final BitSet WWW_FORM_URL_SAFE = new BitSet(256);

    // Static initializer for www_form_url
    static {
        // alpha characters
        for (int i = 'a'; i <= 'z'; i++) {
            WWW_FORM_URL_SAFE.set(i);
        }
        for (int i = 'A'; i <= 'Z'; i++) {
            WWW_FORM_URL_SAFE.set(i);
        }
        // numeric characters
        for (int i = '0'; i <= '9'; i++) {
            WWW_FORM_URL_SAFE.set(i);
        }
        // special chars
        WWW_FORM_URL_SAFE.set('-');
        WWW_FORM_URL_SAFE.set('_');
        WWW_FORM_URL_SAFE.set('.');
        WWW_FORM_URL_SAFE.set('*');
        // blank to be replaced with +
        WWW_FORM_URL_SAFE.set(' ');
    }

    static String HEX_CHARS = "0123456789ABCDEF";

    public static final String encodeUrl(final byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        BitSet urlsafe = WWW_FORM_URL_SAFE;

        final StringWriter buffer = new StringWriter();
        for (final byte c : bytes) {
            int b = c;
            if (b < 0) {
                b = 256 + b;
            }
            if (urlsafe.get(b)) {
                if (b == ' ') {
                    b = '+';
                }
                buffer.write(b);
            } else {
                buffer.write(ESCAPE_CHAR);
                final char hex1 = HEX_CHARS.charAt((b >> 4)&0xf);
                final char hex2 = HEX_CHARS.charAt(b&0xf);
                buffer.write(hex1);
                buffer.write(hex2);
            }
        }
        return buffer.getBuffer().toString();
    }

    public static class Response
    {
        int status = -1;
        Map<String,List<String>> headers = new HashMap<>();
        byte[] body;

        public int getStatus() {
            return this.status;
        }

        public Map<String, List<String>> getHeaders() {
            return this.headers;
        }

        public List<String> getHeader(String _k) {
            return this.headers.get(_k);
        }

        public String getHeaderString(String _k) {
            return this.headers.get(_k).get(0);
        }

        public byte[] getBody() {
            return this.body;
        }

        public String getBodyAsString() {
            return getBodyAsString(StandardCharsets.UTF_8);
        }
        public String getBodyAsString(Charset _cs) {
            return new String(this.body, _cs);
        }
    }
}
