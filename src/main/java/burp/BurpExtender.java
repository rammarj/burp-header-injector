package burp;

import java.util.Arrays;
import java.util.List;
import burp.tab.Tab;

/**
 *
 * @author Joaquin R. Martinez
 */
public class BurpExtender implements IBurpExtender, IHttpListener {

	private IBurpExtenderCallbacks ibec;
	private Tab tab;
	private IExtensionHelpers helpers;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks ibec) {
		this.ibec = ibec;
		helpers = ibec.getHelpers();
		tab = new Tab(this.ibec);
		ibec.registerHttpListener(this);
		ibec.addSuiteTab(this.tab);
	}

	@Override
	public void processHttpMessage(int flag, boolean isRequest, IHttpRequestResponse message) {
		if (isRequest)
			return;

		if (IBurpExtenderCallbacks.TOOL_PROXY != flag && IBurpExtenderCallbacks.TOOL_SPIDER != flag)
			return;

		IRequestInfo req = this.helpers.analyzeRequest(message);
		if (tab.isInScopeOnly() && !this.ibec.isInScope(req.getUrl()))
			return;

		if (this.tab.alreadyExists(req.getUrl().toString())) {
			return;
		}

		List<String> headers = req.getHeaders();
		updateHeaders(headers);

		boolean isPost = "post".equals(req.getMethod().toLowerCase());
		byte[] body = null;
		if (isPost) {
			body = Arrays.copyOfRange(message.getRequest(), req.getBodyOffset(), message.getRequest().length);
		}
		
		byte[] newMsg = helpers.buildHttpMessage(headers, body);
		IHttpRequestResponse newResponse = this.ibec.makeHttpRequest(message.getHttpService(), newMsg);
		byte[] response = newResponse.getResponse();
		if (this.helpers.indexOf(response, "burp.header.injector".getBytes(), false, 0, response.length - 1) != -1) {
			ibec.printOutput("reflected in "+req.getUrl());
			this.tab.sendToTable(newResponse);
		}
	}

	private void updateHeaders(List<String> headers) {
		updateHostAndOrigin(headers);
		headers.add("X-Forwarded-For: burp.header.injector.xff");
		headers.add("X-Forwarded-Proto: burp.header.injector.xfproto");
		headers.add("X-Forwarded-Host: burp.header.injector.xfh");
	}

	private void updateHostAndOrigin(List<String> headers) {
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
	}

}
