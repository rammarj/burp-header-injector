package burp.tab;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
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
	private IMessageEditor requestMessageEditor, responseMessageEditor;
	private RequestsTable requestsTable;
	private boolean inScopeOnly;

	public Tab(IBurpExtenderCallbacks ibec) {
		super(new GridLayout());
		IExtensionHelpers helpers = ibec.getHelpers();
		this.requestsTable = createRequestsTable(helpers);
		this.requestMessageEditor = createRequestMessageEditor(ibec);
		this.responseMessageEditor = createResponseMessageEditor(ibec);
		
		add(new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, createLeftSidePanel(), createHttpMessageTab()));
		ibec.customizeUiComponent(this);
	}

	private JTabbedPane createHttpMessageTab() {
		JTabbedPane tabPane = new JTabbedPane();
		tabPane.add("Request", this.requestMessageEditor.getComponent());
		tabPane.add("Response", this.responseMessageEditor.getComponent());
		return tabPane;
	}

	private JPanel createLeftSidePanel() {
		JPanel leftPanel = new JPanel(new BorderLayout());
		JCheckBox inScopeCheckBox = new JCheckBox("validate only in scope domains.");
		inScopeCheckBox.addChangeListener(e -> this.inScopeOnly = inScopeCheckBox.isSelected());
		leftPanel.add(inScopeCheckBox, BorderLayout.NORTH);
		JScrollPane requestTableScroll = createTableScroll();
		leftPanel.add(requestTableScroll, BorderLayout.CENTER);
		leftPanel.add(createButtonsPanel(), BorderLayout.SOUTH);
		return leftPanel;
	}

	private JScrollPane createTableScroll() {
		JScrollPane requestTableScroll = new JScrollPane();
		requestTableScroll.setViewportView(requestsTable);
		Border tableBorder = new TitledBorder(new LineBorder(Color.BLACK), "Suspicious List");
		requestTableScroll.setBorder(tableBorder);
		return requestTableScroll;
	}

	private RequestsTable createRequestsTable(IExtensionHelpers helpers) {
		return new RequestsTable(helpers) {
			private static final long serialVersionUID = 1L;

			@Override
			public void rowSelectionChanged(IHttpRequestResponse httpReqResU1) {
				requestMessageEditor.setMessage(httpReqResU1.getRequest(), true);
				responseMessageEditor.setMessage(httpReqResU1.getResponse(), false);
			}
		};
	}

	private IMessageEditor createResponseMessageEditor(IBurpExtenderCallbacks ibec) {
		return ibec.createMessageEditor(new IMessageEditorController() {
			@Override
			public IHttpService getHttpService() {
				return new HttpServiceImpl(ibec.getHelpers().analyzeRequest(requestsTable.getSelectedMessage()).getUrl());
			}

			@Override
			public byte[] getRequest() {
				return null;
			}

			@Override
			public byte[] getResponse() {
				return responseMessageEditor.getMessage();
			}
		}, false);
	}

	private IMessageEditor createRequestMessageEditor(IBurpExtenderCallbacks ibec) {
		return ibec.createMessageEditor(new IMessageEditorController() {
			@Override
			public IHttpService getHttpService() {
				return new HttpServiceImpl(ibec.getHelpers().analyzeRequest(requestsTable.getSelectedMessage()).getUrl());
			}

			@Override
			public byte[] getRequest() {
				return requestMessageEditor.getMessage();
			}

			@Override
			public byte[] getResponse() {
				return null;
			}
		}, false);
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

	public boolean alreadyExists(String url) {
		return this.requestsTable.alreadyExists(url);
	}


	@Override
	public String getTabCaption() {
		return "Header injector";
	}

	@Override
	public Component getUiComponent() {
		return this;
	}

	public boolean isInScopeOnly() {
		return inScopeOnly;
	}
}
