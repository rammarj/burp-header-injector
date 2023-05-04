package burp.tab;

import java.util.HashMap;
import java.util.Map;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;

public abstract class RequestsTable extends JTable implements ListSelectionListener {

	private static final long serialVersionUID = 1L;
	private final DefaultTableModel requestsModel;
	private Map<String, IHttpRequestResponse> requestsList;
	private int contRequests;
	private final IExtensionHelpers helpers;

	public RequestsTable(IExtensionHelpers helpers) {
		this.requestsModel = new DefaultTableModel(new String[] { "#", "method", "url", "Status" }, 0);
		this.requestsList = new HashMap<>();
		this.contRequests = 0;
		setModel(this.requestsModel);
		this.helpers = helpers;
		setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		getSelectionModel().addListSelectionListener(this);
	}

	public abstract void rowSelectionChanged(IHttpRequestResponse httpReqResU1);

	@Override
	public void valueChanged(ListSelectionEvent e) {
		IHttpRequestResponse message = getSelectedMessage();
		if (message != null) {
			rowSelectionChanged(message);
		}
	}

	public void addRow(IHttpRequestResponse original) {
		IRequestInfo requestInfo = this.helpers.analyzeRequest(original);
		if (!alreadyExists(requestInfo.getUrl().toString())) {
			IResponseInfo responseInfo = this.helpers.analyzeResponse(original.getResponse());
			this.requestsList.put(requestInfo.getUrl().toString(), original);
			String requestCount = String.valueOf(this.contRequests++);
			String statusCode = String.valueOf(responseInfo.getStatusCode());
			String[] row = new String[] { requestCount, requestInfo.getMethod(), requestInfo.getUrl().toString(),
					statusCode };
			this.requestsModel.addRow(row);
		}
	}

	public boolean alreadyExists(String url) {
		return this.requestsList.containsKey(url);
	}

	public void clear() {
		this.contRequests = 0;
		this.requestsList.clear();
		this.requestsModel.setRowCount(0);
	}

	public IHttpRequestResponse getSelectedMessage() {
		int selectedRow = getSelectedRow();
		if (selectedRow != -1) {
			String key = getValueAt(selectedRow, 2).toString();
			return requestsList.get(key);
		}
		return null;
	}
}
