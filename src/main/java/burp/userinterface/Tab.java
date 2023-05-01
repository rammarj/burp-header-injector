package burp.userinterface;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.ITab;
import burp.util.HttpServiceImpl;

/**
 *
 * @author Joaquin R. Martinez
 */
public class Tab extends JPanel implements ITab {

	private static final long serialVersionUID = 1L;
	private IMessageEditor msgeditorRequest, msgeditorResponse;
	private RequestsTable requestsTable;

	public Tab(IBurpExtenderCallbacks ibec) {
		super(new GridLayout());
		IExtensionHelpers helpers = ibec.getHelpers();
		this.requestsTable = new RequestsTable(helpers) {
			private static final long serialVersionUID = 1L;

			@Override
			public void rowSelectionChanged(IHttpRequestResponse httpReqResU1) {
				msgeditorRequest.setMessage(httpReqResU1.getRequest(), true);
				msgeditorResponse.setMessage(httpReqResU1.getResponse(), false);
			}
		};
		this.msgeditorRequest = ibec.createMessageEditor(new IMessageEditorController() {
			@Override
			public IHttpService getHttpService() {
				return new HttpServiceImpl(helpers.analyzeRequest(requestsTable.getSelectedMessage()).getUrl());
			}

			@Override
			public byte[] getRequest() {
				return msgeditorRequest.getMessage();
			}

			@Override
			public byte[] getResponse() {
				return null;
			}
		}, false);
		this.msgeditorResponse = ibec.createMessageEditor(new IMessageEditorController() {
			@Override
			public IHttpService getHttpService() {
				return new HttpServiceImpl(helpers.analyzeRequest(requestsTable.getSelectedMessage()).getUrl());
			}

			@Override
			public byte[] getRequest() {
				return null;
			}

			@Override
			public byte[] getResponse() {
				return msgeditorResponse.getMessage();
			}
		}, false);


		JPanel leftPanel = new JPanel(new BorderLayout());
		JScrollPane sclTbSuspiciuslRequests = new JScrollPane();
		sclTbSuspiciuslRequests.setViewportView(requestsTable);
		Border brdPnlSuspicius = new TitledBorder(new LineBorder(Color.BLACK), "Suspicious List");
		sclTbSuspiciuslRequests.setBorder(brdPnlSuspicius);
		leftPanel.add(sclTbSuspiciuslRequests, BorderLayout.CENTER);
		leftPanel.add(createButtonsPanel(), BorderLayout.SOUTH);
		JTabbedPane tab_principal = new JTabbedPane();
		tab_principal.add("Request", this.msgeditorRequest.getComponent());
		tab_principal.add("Response", this.msgeditorResponse.getComponent());

		this.add(new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, tab_principal));
		ibec.customizeUiComponent(this);
	}

	private JPanel createButtonsPanel() {
		JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		JButton cleanButton = new JButton("clear table");
		cleanButton.addActionListener(e -> this.requestsTable.clear());
		panel.add(cleanButton);
		return panel;
	}

	public void sendToTable(IHttpRequestResponse original) {
		this.requestsTable.addRow(original);
	}

	public boolean alreadyExists(IHttpRequestResponse original) {
		return this.requestsTable.alreadyExists(original);
	}


	@Override
	public String getTabCaption() {
		return "Header injector";
	}

	@Override
	public Component getUiComponent() {
		return this;
	}

}
