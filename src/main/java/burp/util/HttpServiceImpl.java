
package burp.util;

import burp.IHttpService;
import burp.IRequestInfo;
import java.net.URL;
/**
 *
 * @author Joaquin R. Martinez
 */
public class HttpServiceImpl implements IHttpService {

    private URL url;

    public HttpServiceImpl(URL url) {
        this.url = url;
    }

    public HttpServiceImpl(IRequestInfo info) {
        this(info.getUrl());
    }

    @Override
    public String getHost() {
        return this.url.getHost();
    }

    @Override
    public int getPort() {
        return this.url.getPort();
    }

    @Override
    public String getProtocol() {
        return this.url.getProtocol();
    }

}
