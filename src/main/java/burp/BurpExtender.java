package burp;

import burp.userinterface.UInterface;
import java.awt.Component;
import java.util.Arrays;
import java.util.List;

/**
 *
 * @author Joaquin R. Martinez
 */
public class BurpExtender implements IBurpExtender, IHttpListener {

    private IBurpExtenderCallbacks ibec;
    private UInterface uInterface;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks ibec) {
        this.ibec = ibec;
        helpers = ibec.getHelpers();
        uInterface = new UInterface(this.ibec);
        ibec.registerHttpListener(this);
        ibec.addSuiteTab(new ITab() {
            @Override
            public String getTabCaption() {
                return "Header injector";
            }

            @Override
            public Component getUiComponent() {
                return uInterface;
            }
        });
    }

    @Override
    public void processHttpMessage(int flag, boolean isRequest, IHttpRequestResponse message) {
        IRequestInfo req = this.helpers.analyzeRequest(message);
        if (!isRequest&&(IBurpExtenderCallbacks.TOOL_PROXY == flag||IBurpExtenderCallbacks.TOOL_SPIDER == flag)
                && (this.ibec.isInScope(req.getUrl()))) {
            if (this.uInterface.alreadyExists(message)) {
                return;
            }
            List<String> headers = req.getHeaders();
            for (int i = headers.size() - 1; i >= 0; i--) {
                String header = (String) headers.get(i);
                if (header.startsWith("Host:")) {
                    header = header + ".burp.header.injector.host";
                    headers.remove(i);
                    headers.add(i, header);
                }
                if (header.startsWith("Origin")) {
                    headers.remove(i);
                }
            }
            headers.add("X-Forwarded-For: burp.header.injector.xff");
            headers.add("X-Forwarded-Proto: burp.header.injector.xfproto");
            headers.add("X-Forwarded-Host: burp.header.injector.xfh");
            
            byte[] newMsg = helpers.buildHttpMessage(headers, ("post".equals(req.getMethod().toLowerCase()))?Arrays.copyOfRange(message.getRequest(), req.getBodyOffset(), message.getRequest().length):null);   
            IHttpRequestResponse newResponse = this.ibec.makeHttpRequest(message.getHttpService(), newMsg);
            byte[] response = newResponse.getResponse();
            if (this.helpers.indexOf(response, "burp.header.injector".getBytes(), false, 0, response.length - 1) != -1) {
                this.uInterface.sendToTable(newResponse);
            }
        }
    }

}
